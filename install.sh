#!/bin/bash

# ========================================================
# Script: install.sh
# Descripción: Instalador mejorado para IPsec Tunnel Monitor
# Autor: Usuario
# ========================================================

set -euo pipefail  # Salir en caso de error, variable no definida o pipe que falle

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Funciones auxiliares
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

# Verificar si el script se ejecuta como root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Este script debe ejecutarse como root (usa sudo)"
        exit 1
    fi
}

# Verificar dependencias
check_dependencies() {
    local missing_deps=()
    
    # Verificar Ruby
    if ! command -v ruby &> /dev/null; then
        missing_deps+=("ruby")
    fi
    
    # Verificar systemctl
    if ! command -v systemctl &> /dev/null; then
        missing_deps+=("systemd")
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Dependencias faltantes: ${missing_deps[*]}"
        log_info "Para Ubuntu/Debian: sudo apt update && sudo apt install ruby"
        log_info "Para CentOS/RHEL: sudo yum install ruby"
        exit 1
    fi
}

# Validar IP
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -ra ADDR <<< "$ip"
        for i in "${ADDR[@]}"; do
            if [[ $i -gt 255 ]]; then
                return 1
            fi
        done
        return 0
    else
        return 1
    fi
}

# Función para obtener IPs de FortiGate
get_fortigate_ips() {
    local ips=()
    local input

    echo -e "\n${BLUE}Configuración de IPs de FortiGate:${NC}" >&2
    echo "Ingrese las IPs de FortiGate para test de conectividad" >&2
    echo "(presione Enter sin escribir nada para terminar)" >&2

    while true; do
        read -p "IP FortiGate $(( ${#ips[@]} + 1 )) [o Enter para terminar]: " input

        if [[ -z "$input" ]]; then
            if [[ ${#ips[@]} -eq 0 ]]; then
                log_warn "Debe ingresar al menos una IP. Usando IPs por defecto." >&2
                ips=("1.1.1.1" "8.8.8.8")
            fi
            break
        fi

        if validate_ip "$input"; then
            ips+=("$input")
            log_info "IP añadida: $input" >&2
        else
            log_error "IP inválida: $input. Por favor, intente nuevamente." >&2
        fi
    done

    # Solo imprime las IPs válidas por stdout (una por línea)
    printf '%s\n' "${ips[@]}"
}

# Función principal de instalación
main() {
    echo -e "${BLUE}==== Instalador del IPsec Tunnel Monitor ====${NC}"
    echo "Este script configurará y instalará el monitor de túneles IPsec"
    echo ""
    
    # Verificaciones iniciales
    check_root
    check_dependencies
    
    # Variables por defecto
    local INSTALL_DIR="/opt/ipsec-tunnel-monitor"
    local LOG_DIR="/var/log/ipsec-tunnel-monitor"
    local CONFIG_DIR="/etc/ipsec-tunnel-monitor"
    local CONFIG_FILE="$CONFIG_DIR/config.yml"
    local SYSTEMD_DIR="/etc/systemd/system"
    local SCRIPT_NAME="ipsec_monitor.rb"
    local SERVICE_NAME="ipsec-monitor.service"
    local TIMER_NAME="ipsec-monitor.timer"
    
    # === Preguntar configuración al usuario ===
    
    # Directorio de instalación
    echo -e "\n${BLUE}Configuración de directorios:${NC}"
    read -p "Directorio de instalación [$INSTALL_DIR]: " user_install_dir
    INSTALL_DIR=${user_install_dir:-$INSTALL_DIR}
    
    # IP del servidor (opcional)
    echo -e "\n${BLUE}Configuración del servidor:${NC}"
    read -p "IP del servidor (opcional, Enter para omitir): " SERVER_IP
    while [[ -n "$SERVER_IP" ]] && ! validate_ip "$SERVER_IP"; do
        log_error "IP inválida: $SERVER_IP"
        read -p "IP del servidor (opcional, Enter para omitir): " SERVER_IP
    done
    
    # Directorio de logs
    read -p "Directorio para logs [$LOG_DIR]: " user_log_dir
    LOG_DIR=${user_log_dir:-$LOG_DIR}
    
    # Archivo de configuración IPsec
    echo -e "\n${BLUE}Configuración de IPsec:${NC}"
    read -p "Archivo de configuración IPsec [/etc/ipsec.conf]: " IPSEC_CONFIG_FILE
    IPSEC_CONFIG_FILE=${IPSEC_CONFIG_FILE:-/etc/ipsec.conf}
    
    # Obtener IPs de FortiGate
    echo -e "\n${BLUE}Configuración de IPs de FortiGate:${NC}"
    mapfile -t FORTIGATE_IPS_ARRAY < <(get_fortigate_ips)
    
    # Intervalo del timer
    echo -e "\n${BLUE}Configuración del temporizador:${NC}"
    echo "Intervalo de ejecución en minutos (recomendado: 5)"
    read -p "Intervalo en minutos [5]: " TIMER_INTERVAL
    TIMER_INTERVAL=${TIMER_INTERVAL:-5}
    
    # Validar que el intervalo sea numérico
    while ! [[ "$TIMER_INTERVAL" =~ ^[0-9]+$ ]]; do
        log_error "El intervalo debe ser un número"
        read -p "Intervalo en minutos [5]: " TIMER_INTERVAL
        TIMER_INTERVAL=${TIMER_INTERVAL:-5}
    done
    
    # === Mostrar resumen de configuración ===
    echo -e "\n${YELLOW}=== RESUMEN DE CONFIGURACIÓN ===${NC}"
    echo "  ➤ Directorio de instalación: $INSTALL_DIR"
    echo "  ➤ Directorio de logs: $LOG_DIR"
    echo "  ➤ Archivo de configuración: $CONFIG_FILE"
    echo "  ➤ Configuración IPsec: $IPSEC_CONFIG_FILE"
    [[ -n "$SERVER_IP" ]] && echo "  ➤ IP del servidor: $SERVER_IP"
    echo "  ➤ IPs FortiGate: ${FORTIGATE_IPS_ARRAY[*]}"
    echo "  ➤ Intervalo del timer: ${TIMER_INTERVAL} minutos"
    echo ""
    
    read -p "¿Desea continuar con la instalación? (s/n): " CONFIRM
    if [[ "$CONFIRM" != "s" && "$CONFIRM" != "S" ]]; then
        log_warn "Instalación cancelada por el usuario."
        exit 1
    fi
    
    # === Verificar archivos requeridos ===
    log_info "Verificando archivos requeridos..."
    local required_files=("$SCRIPT_NAME" "$SERVICE_NAME" "$TIMER_NAME")
    for file in "${required_files[@]}"; do
        if [[ ! -f "./$file" ]]; then
            log_error "Archivo requerido no encontrado: $file"
            exit 1
        fi
    done
    
    # === Crear directorios ===
    log_info "Creando directorios..."
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"
    
    # === Realizar backup de configuración existente ===
    if [[ -f "$CONFIG_FILE" ]]; then
        local backup_file="${CONFIG_FILE}.backup.$(date +%s)"
        log_warn "Configuración existente encontrada. Creando backup..."
        cp "$CONFIG_FILE" "$backup_file"
        log_info "Backup guardado en: $backup_file"
    fi
    
    # === Copiar script principal ===
    log_info "Copiando script principal..."
    cp "./$SCRIPT_NAME" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/$SCRIPT_NAME"
    
    # === Generar archivo de configuración YAML ===
    log_info "Generando archivo de configuración..."
    cat > "$CONFIG_FILE" << EOF
# Archivo de configuración de IPsec Tunnel Monitor
# Generado automáticamente el $(date)

# IP del servidor (opcional)
server_ip: ${SERVER_IP:-null}

# Directorio donde se guardarán los logs
log_directory: "$LOG_DIR"

# Lista de IPs remotas para test de conectividad
fortigate_ips:
EOF
    
    # Añadir IPs de FortiGate al archivo de configuración
    for ip in "${FORTIGATE_IPS_ARRAY[@]}"; do
        echo "  - \"$ip\"" >> "$CONFIG_FILE"
    done
    
    cat >> "$CONFIG_FILE" << EOF

# Ruta al archivo de configuración de IPsec
ipsec_config_file: "$IPSEC_CONFIG_FILE"

# Configuración adicional
# Tiempo de espera para ping (segundos)
ping_timeout: 3

# Número de pings para verificar conectividad
ping_count: 2
EOF
    
    # === Generar archivos de systemd personalizados ===
    log_info "Configurando servicios systemd..."
    
    # Copiar y modificar el archivo timer
    sed "s/OnUnitActiveSec=5min/OnUnitActiveSec=${TIMER_INTERVAL}min/" "./$TIMER_NAME" > "$SYSTEMD_DIR/$TIMER_NAME"
    
    # Copiar service file
    cp "./$SERVICE_NAME" "$SYSTEMD_DIR/"
    
    # === Configurar permisos ===
    log_info "Configurando permisos..."
    chmod 644 "$CONFIG_FILE"
    chmod 644 "$SYSTEMD_DIR/$SERVICE_NAME"
    chmod 644 "$SYSTEMD_DIR/$TIMER_NAME"
    
    # === Verificar configuración de IPsec ===
    if [[ ! -f "$IPSEC_CONFIG_FILE" ]]; then
        log_warn "Archivo de configuración IPsec no encontrado: $IPSEC_CONFIG_FILE"
        log_warn "Asegúrese de que strongSwan esté instalado y configurado."
    fi
    
    # === Recargar systemd ===
    log_info "Recargando systemd..."
    systemctl daemon-reload
    
    # === Habilitar y iniciar el timer ===
    log_info "Habilitando y iniciando el temporizador..."
    if systemctl enable "$TIMER_NAME"; then
        log_success "Timer habilitado exitosamente"
    else
        log_error "Error al habilitar el timer"
        exit 1
    fi
    
    if systemctl start "$TIMER_NAME"; then
        log_success "Timer iniciado exitosamente"
    else
        log_error "Error al iniciar el timer"
        exit 1
    fi
    
    # === Verificar estado ===
    log_info "Verificando estado del servicio..."
    if systemctl is-active --quiet "$TIMER_NAME"; then
        log_success "Timer está activo"
    else
        log_warn "Timer no está activo"
    fi
    
    # === Crear script de desinstalación ===
    log_info "Creando script de desinstalación..."
    cat > "$INSTALL_DIR/uninstall.sh" << 'EOF'
#!/bin/bash
echo "Desinstalando IPsec Tunnel Monitor..."
systemctl stop ipsec-monitor.timer || true
systemctl disable ipsec-monitor.timer || true
rm -f /etc/systemd/system/ipsec-monitor.service
rm -f /etc/systemd/system/ipsec-monitor.timer
systemctl daemon-reload
echo "¿Desea eliminar también los logs y configuración? (s/n):"
read -r response
if [[ "$response" == "s" || "$response" == "S" ]]; then
    rm -rf /etc/ipsec-tunnel-monitor
    rm -rf LOG_DIR_PLACEHOLDER
    rm -rf INSTALL_DIR_PLACEHOLDER
fi
echo "Desinstalación completada"
EOF
    
    # Personalizar el script de desinstalación
    sed -i "s|LOG_DIR_PLACEHOLDER|$LOG_DIR|g" "$INSTALL_DIR/uninstall.sh"
    sed -i "s|INSTALL_DIR_PLACEHOLDER|$INSTALL_DIR|g" "$INSTALL_DIR/uninstall.sh"
    chmod +x "$INSTALL_DIR/uninstall.sh"
    
    # === Mostrar información final ===
    echo ""
    log_success "¡Instalación completada exitosamente!"
    echo ""
    echo -e "${BLUE}Información del sistema instalado:${NC}"
    echo "  ➤ Script instalado en: $INSTALL_DIR"
    echo "  ➤ Configuración en: $CONFIG_FILE"
    echo "  ➤ Logs en: $LOG_DIR"
    echo "  ➤ Timer ejecutándose cada $TIMER_INTERVAL minutos"
    echo ""
    echo -e "${BLUE}Comandos útiles:${NC}"
    echo "  ➤ Ver estado del timer: systemctl status $TIMER_NAME"
    echo "  ➤ Ver logs del servicio: journalctl -u $SERVICE_NAME"
    echo "  ➤ Ejecutar manualmente: $INSTALL_DIR/$SCRIPT_NAME"
    echo "  ➤ Desinstalar: $INSTALL_DIR/uninstall.sh"
    echo ""
    echo -e "${YELLOW}NOTA:${NC} El primer chequeo se ejecutará en 2 minutos tras el boot"
    echo "      y posteriormente cada $TIMER_INTERVAL minutos."
}

# Ejecutar función principal
main "$@"
