# IPsec Tunnel Monitor

Un sistema de monitoreo y recuperación automática para túneles IPsec que detecta y reinicia conexiones caídas.

## Descripción

El IPsec Tunnel Monitor es una herramienta diseñada para supervisar continuamente el estado de los túneles IPsec en sistemas Linux. Cuando detecta túneles inactivos, intenta reiniciarlos automáticamente mientras registra todo el proceso, ayudando a mantener las conexiones VPN estables y operativas.

## Características

- 🔍 Monitoreo automático de túneles IPsec
- 🔄 Reinicio automatizado de conexiones caídas
- 📊 Verificación de conectividad con endpoints remotos
- 📝 Sistema de registro detallado
- ⏱️ Ejecución periódica mediante systemd timers
- 🧰 Instalación fácil mediante script interactivo

## Requisitos

- Sistema operativo Linux con systemd
- Ruby (2.0+)
- strongSwan instalado y configurado
- Privilegios de root para la instalación y ejecución

## Instalación

1. Clone este repositorio:

   ```bash
   git clone https://github.com/username/ipsec-tunnel-monitor.git
   cd ipsec-tunnel-monitor
   ```
2. Ejecute el script de instalación:

   ```bash
   sudo ./install.sh
   ```
3. Siga las instrucciones del asistente de instalación para personalizar la configuración.

## Configuración

El archivo de configuración se encuentra en `/etc/ipsec-tunnel-monitor/config.yml` y contiene las siguientes opciones:

```yaml
# Archivo de configuración de IPsec Tunnel Monitor

# IP del servidor (opcional)
server_ip: null

# Directorio donde se guardarán los logs
log_directory: "/var/log/ipsec-tunnel-monitor"

# Lista de IPs remotas para test de conectividad
fortigate_ips:
  - "1.1.1.1"
  - "8.8.8.8"

# Ruta al archivo de configuración de IPsec
ipsec_config_file: "/etc/ipsec.conf"

# Configuración adicional
# Tiempo de espera para ping (segundos)
ping_timeout: 3

# Número de pings para verificar conectividad
ping_count: 2
```

## Uso

El servicio se ejecuta automáticamente cada 5 minutos (o el intervalo configurado) a través de systemd.

### Comandos útiles

- Ver estado del timer:

  ```bash
  systemctl status ipsec-monitor.timer
  ```
- Ver logs del servicio:

  ```bash
  journalctl -u ipsec-monitor.service
  ```
- Ejecutar el monitor manualmente:

  ```bash
  /opt/ipsec-tunnel-monitor/ipsec_monitor.rb
  ```

## Registro de actividad

Los registros se almacenan en:

- `/var/log/ipsec-tunnel-monitor/` (o el directorio configurado)
- `journalctl` del sistema

## Desinstalación

Para desinstalar el monitor, ejecute:

```bash
sudo /opt/ipsec-tunnel-monitor/uninstall.sh
```

## Estructura del proyecto

- `ipsec_monitor.rb`: Script principal que realiza el monitoreo
- `install.sh`: Script de instalación interactivo
- `config.yml`: Archivo de configuración
- `ipsec-monitor.service`: Unidad de servicio para systemd
- `ipsec-monitor.timer`: Temporizador para ejecución periódica

## Solución de problemas

Si encuentra problemas, verifique:

1. Que strongSwan esté correctamente instalado y configurado
2. Que el archivo `/etc/ipsec.conf` exista y contenga configuraciones válidas
3. Que las IPs remotas sean accesibles desde su servidor
4. Los registros para obtener información detallada sobre los errores

## Licencia

Este proyecto está disponible bajo la licencia MIT. Consulte el archivo LICENSE para más detalles.

## Contribuciones

Las contribuciones son bienvenidas. Por favor, siéntase libre de enviar pull requests o abrir issues para mejorar la funcionalidad o reportar problemas.
