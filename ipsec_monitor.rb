require 'fileutils'
require 'yaml'
require 'timeout'
require 'date'
require 'logger'
require 'rbconfig'

# Configuración global de timeout
TIMEOUT_SECONDS = 30

# Clase para manejar la configuración
class IPsecConfig
  attr_reader :log_directory, :fortigate_ips, :ipsec_config_file,
              :server_ip, :ping_timeout, :ping_count

  def initialize(config_file = '/etc/ipsec-tunnel-monitor/config.yml')
    @config = load_config(config_file)
    validate_config

    @log_directory = @config['log_directory'] || "/var/log/ipsec-monitor"
    @fortigate_ips = @config['fortigate_ips'] || ['1.1.1.1', '8.8.8.8']
    @ipsec_config_file = @config['ipsec_config_file'] || '/etc/ipsec.conf'
    @server_ip = @config['server_ip']
    @ping_timeout = @config['ping_timeout'] || 3
    @ping_count = @config['ping_count'] || 2
  end

  private

  def load_config(config_file)
    YAML.load_file(config_file)
  rescue Errno::ENOENT
    abort("❌ Archivo de configuración no encontrado: #{config_file}")
  rescue => e
    abort("❌ Error al cargar configuración: #{e.message}")
  end

  def validate_config
    unless @config.is_a?(Hash)
      abort("❌ Archivo de configuración inválido")
    end
  end
end

# Clase principal para el monitor IPsec
class IPsecMonitor
  def initialize(config)
    @config = config
    @logger = setup_logger
    @tunnels = load_tunnels_from_config

    # Log de información inicial
    @logger.info("=== IPsec Monitor iniciado ===")
    @logger.info("Configuración cargada desde: /etc/ipsec-tunnel-monitor/config.yml")
    @logger.info("IPs de FortiGate: #{@config.fortigate_ips.join(', ')}")
    @logger.info("Archivo IPsec: #{@config.ipsec_config_file}")
    log_debug_info
  end

  def run
    begin
      Timeout::timeout(TIMEOUT_SECONDS) do
        validate_and_check_tunnels
      end
    rescue Timeout::Error
      @logger.fatal("⏰ Script interrumpido por timeout (#{TIMEOUT_SECONDS}s)")
    rescue => e
      @logger.fatal("💥 Error fatal: #{e.message}")
      @logger.fatal("Backtrace: #{e.backtrace.join("\n")}")
    ensure
      @logger.info("=== Ejecución finalizada ===")
    end
  end

  private

  def setup_logger
    FileUtils.mkdir_p(@config.log_directory) unless Dir.exist?(@config.log_directory)

    date = Date.today.strftime('%Y-%m-%d')
    logfile = File.join(@config.log_directory, "ipsec_tunnel_monitor_#{date}.log")

    logger = Logger.new(logfile)
    logger.formatter = proc do |severity, datetime, progname, msg|
      "#{datetime.strftime('%Y-%m-%d %H:%M:%S')} [#{severity}] #{msg}\n"
    end

    # También escribir a syslog para systemd
    logger.level = Logger::INFO
    logger
  end

  def log_debug_info
    begin
      File.open('/var/log/ipsec_monitor_debug.log', 'a') do |f|
        f.puts "[#{Time.now}] Ejecutado por #{ENV['USER'] || 'desconocido'}"
        f.puts "[#{Time.now}] PATH: #{ENV['PATH'] || 'no definido'}"
        f.puts "[#{Time.now}] Túneles encontrados: #{@tunnels.size}"
      end
    rescue => e
      @logger.warn("⚠️  Error escribiendo log de depuración: #{e.message}")
    end
  end

  def load_tunnels_from_config
    tunnels = []

    unless File.exist?(@config.ipsec_config_file)
      @logger.error("❌ Archivo IPsec no encontrado: #{@config.ipsec_config_file}")
      return tunnels
    end

    begin
      File.foreach(@config.ipsec_config_file) do |line|
        line.strip!
        next if line.empty? || line.start_with?('#')

        if line.start_with?("conn ")
          tunnel_name = line.split(" ")[1]
          next if tunnel_name == '%default'  # Ignorar configuración por defecto
          tunnels << tunnel_name
        end
      end

      if tunnels.empty?
        @logger.warn("⚠️  No se encontraron túneles en #{@config.ipsec_config_file}")
      else
        @logger.info("🔗 Túneles encontrados: #{tunnels.join(', ')}")
      end
    rescue => e
      @logger.error("❌ Error leyendo archivo IPsec: #{e.message}")
    end

    tunnels
  end

  def run_command(command, description = nil)
    desc = description || command
    @logger.info("🔧 #{desc}")

    begin
      result = `#{command} 2>&1`
      exit_status = $?.exitstatus

      if exit_status == 0
        @logger.info("✅ Comando exitoso: #{desc}")
        @logger.debug("Salida: #{result}") unless result.strip.empty?
      else
        @logger.error("❌ Error en comando (exit #{exit_status}): #{desc}")
        @logger.error("Salida de error: #{result}") unless result.strip.empty?
      end

      { success: exit_status == 0, output: result, exit_status: exit_status }
    rescue => e
      @logger.error("💥 Excepción ejecutando comando: #{e.message}")
      { success: false, output: e.message, exit_status: -1 }
    end
  end

  def ip_reachable?(ip)
    @logger.info("🏓 Verificando conectividad con #{ip}...")

    cmd = "ping -c #{@config.ping_count} -W #{@config.ping_timeout} #{ip}"
    result = run_command(cmd, "Ping a #{ip}")

    if result[:success]
      @logger.info("✅ #{ip} alcanzable")
      return true
    else
      @logger.error("❌ #{ip} inalcanzable")
      return false
    end
  end

  def get_tunnel_status
    result = run_command('ipsec status', 'Obteniendo estado de túneles')

    # Si el comando falla con código 3, puede indicar que IPsec no está ejecutándose
    # o que todos los túneles están caídos - en este caso debemos reiniciar
    if !result[:success]
      if result[:exit_status] == 3
        @logger.warn("🔄 IPsec status retornó código 3 - posible servicio caído o todos los túneles inactivos")
        return "ERROR_ALL_DOWN"  # Valor especial para indicar que todos los túneles están caídos
      else
        @logger.error("❌ Error desconocido al obtener estado de túneles: #{result[:exit_status]}")
        return nil
      end
    end

    result[:output]
  end

  def check_tunnels
    return if @tunnels.empty?

    status_output = get_tunnel_status

    # Si recibimos el valor especial que indica que todos los túneles están caídos
    if status_output == "ERROR_ALL_DOWN"
      @logger.warn("⚠️ Todos los túneles parecen estar inactivos")
      @logger.warn("📊 Estado: 0/#{@tunnels.size} túneles activos")
      restart_ipsec(@tunnels.size)
      return
    end

    return unless status_output

    active_tunnels = []
    inactive_tunnels = []

    @tunnels.each do |tunnel|
      # Buscar patrones que indiquen que el túnel está activo
      if status_output.match(/#{Regexp.escape(tunnel)}\{.*\}.*INSTALLED/) ||
         status_output.match(/#{Regexp.escape(tunnel)}.*ESTABLISHED.*INSTALLED/)
        active_tunnels << tunnel
        @logger.info("✅ Túnel activo: #{tunnel}")
      else
        inactive_tunnels << tunnel
        @logger.warn("⚠️  Túnel inactivo: #{tunnel}")
      end
    end

    if inactive_tunnels.empty?
      @logger.info("🎉 Todos los túneles están activos (#{active_tunnels.size}/#{@tunnels.size})")
    else
      @logger.warn("⚠️  Túneles inactivos detectados: #{inactive_tunnels.join(', ')}")
      @logger.warn("📊 Estado: #{active_tunnels.size}/#{@tunnels.size} túneles activos")
      restart_ipsec(inactive_tunnels.size)
    end
  end

  def restart_ipsec(inactive_count)
    @logger.warn("🔄 Reiniciando IPsec (#{inactive_count} túneles caídos)")

    # Intentar restart primero
    result = run_command('ipsec restart', 'Reinicio de IPsec')

    if result[:success]
      @logger.info("✅ IPsec reiniciado exitosamente")
      sleep(5)  # Esperar a que se estabilicen las conexiones

      # Verificar que el servicio esté corriendo
      verify_result = run_command('ipsec status', 'Verificación post-reinicio')
      if verify_result[:success]
        @logger.info("✅ Verificación post-reinicio exitosa")
      else
        # Incluso si el status falla con código 3, podría estar bien si el servicio está iniciando
        if verify_result[:exit_status] == 3
          @logger.info("⚠️ IPsec status retornó código 3 después del reinicio - podría estar iniciando")
          # Comprobamos si el proceso está corriendo
          process_check = run_command('pgrep -f charon', 'Verificando proceso charon')
          if process_check[:success]
            @logger.info("✅ Proceso charon detectado - IPsec parece estar operativo")
          else
            @logger.error("❌ No se detecta proceso charon - posible fallo en el reinicio")
          end
        else
          @logger.error("❌ IPsec no responde correctamente después del reinicio")
        end
      end
    else
      @logger.error("❌ Error en reinicio de IPsec")

      # Como fallback, intentar stop/start manual
      @logger.info("🔄 Intentando stop/start manual...")
      stop_result = run_command('ipsec stop', 'Deteniendo IPsec')
      sleep(2)
      start_result = run_command('ipsec start', 'Iniciando IPsec')

      if start_result[:success]
        @logger.info("✅ IPsec iniciado manualmente")
      else
        @logger.error("💥 Error crítico: No se pudo reiniciar IPsec")

        # Si todos los intentos fallan, intentamos reiniciar el servicio systemd
        @logger.info("🔄 Último intento: reinicio vía systemd")
        systemd_result = run_command('systemctl restart strongswan', 'Reiniciando strongswan via systemd')
        if systemd_result[:success]
          @logger.info("✅ Servicio strongswan reiniciado vía systemd")
        else
          # Intentamos con nombres alternativos del servicio
          systemd_result = run_command('systemctl restart strongswan-starter', 'Reiniciando strongswan-starter')
          if systemd_result[:success]
            @logger.info("✅ Servicio strongswan-starter reiniciado vía systemd")
          else
            @logger.error("💥 Todos los intentos de reinicio fallaron")
          end
        end
      end
    end
  end

  def validate_and_check_tunnels
    reachable_ips = @config.fortigate_ips.select { |ip| ip_reachable?(ip) }

    if reachable_ips.empty?
      @logger.error("💀 Ninguna IP remota respondió. Posible problema de conectividad.")
      @logger.error("🚫 No se reiniciarán los túneles como medida de precaución.")
      @logger.info("🔍 IPs probadas: #{@config.fortigate_ips.join(', ')}")
    else
      @logger.info("✅ IPs remotas alcanzables: #{reachable_ips.join(', ')}")
      @logger.info("🔍 Verificando estado de túneles IPsec...")
      check_tunnels
    end
  end
end

# Función para verificar dependencias
def check_dependencies
  missing = []

  # Verificar ipsec command
  unless system('which ipsec > /dev/null 2>&1')
    missing << 'ipsec (strongSwan no instalado?)'
  end

  # Verificar ping command
  unless system('which ping > /dev/null 2>&1')
    missing << 'ping'
  end

  unless missing.empty?
    puts "❌ Dependencias faltantes: #{missing.join(', ')}"
    exit 1
  end
end

# Punto de entrada principal
if $0 == __FILE__
  # Verificar dependencias
  check_dependencies

  # Cargar configuración
  config = IPsecConfig.new

  # Crear y ejecutar monitor
  monitor = IPsecMonitor.new(config)
  monitor.run
end
