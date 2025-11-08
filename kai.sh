#!/usr/bin/env bash

# Exit immediately on error, treat unset vars as error, and fail on pipeline errors
set -euo pipefail
umask 077

SCRIPT_BASENAME="$(basename "$0")"
INSTALL_DIR="${HOME}/.local/komari-agent"
BIN_PATH="${INSTALL_DIR}/bin/komari-agent"
CONFIG_PATH="${INSTALL_DIR}/config.json"
LOG_DIR="${INSTALL_DIR}/logs"
RUN_DIR="${INSTALL_DIR}/run"
SERVICE_NAME="komari-agent"
SYSTEMD_UNIT_PATH="${HOME}/.config/systemd/user/${SERVICE_NAME}.service"
ALPINE_CRON_MARKER="${INSTALL_DIR}/.cron_installed"

DEFAULT_CONFIG_TEMPLATE='{
	"auto_discovery_key": "",
	"disable_auto_update": false,
	"disable_web_ssh": true,
	"memory_mode_available": false,
	"token": "",
	"endpoint": "",
	"interval": 5,
	"ignore_unsafe_cert": false,
	"max_retries": 5,
	"reconnect_interval": 10,
	"info_report_interval": 10,
	"include_nics": "",
	"exclude_nics": "",
	"include_mountpoints": "/",
	"month_rotate": 1,
	"cf_access_client_id": "",
	"cf_access_client_secret": "",
	"memory_include_cache": true,
	"custom_dns": "1.1.1.1,8.8.8.8,223.5.5.5",
	"enable_gpu": false,
	"show_warning": false,
	"custom_ipv4": "",
	"custom_ipv6": "",
	"get_ip_addr_from_nic": true
}'

AMD64_URL="https://github.com/komari-monitor/komari-agent/releases/latest/download/komari-agent-linux-amd64"
ARM64_URL="https://github.com/komari-monitor/komari-agent/releases/latest/download/komari-agent-linux-arm64"

COLOR_INFO="\033[0;36m"
COLOR_WARN="\033[0;33m"
COLOR_ERROR="\033[0;31m"
COLOR_SUCCESS="\033[0;32m"
COLOR_RESET="\033[0m"

die() {
	local msg=$1
	printf "%b[%s]%b %s\n" "${COLOR_ERROR}" "ERROR" "${COLOR_RESET}" "${msg}" >&2
	exit 1
}

log_info() {
	printf "%b[%s]%b %s\n" "${COLOR_INFO}" "INFO" "${COLOR_RESET}" "$1"
}

log_warn() {
	printf "%b[%s]%b %s\n" "${COLOR_WARN}" "WARN" "${COLOR_RESET}" "$1"
}

log_success() {
	printf "%b[%s]%b %s\n" "${COLOR_SUCCESS}" "OK" "${COLOR_RESET}" "$1"
}

# Globals populated by argument parsing
CFG_SOURCE=""
CFG_URL_FOR_AUTO=""
OPT_AUTO_DISCOVERY=""
OPT_TOKEN=""
OPT_ENDPOINT=""
AUTO_MODE=""   # empty, number (minutes) or 'd'
DEBUG_MODE=0
UNINSTALL_ONLY=0
SHOW_LOGS=0

usage() {
	cat <<EOF
Usage: ${SCRIPT_BASENAME} [options]

Options:
	-c <path|url>       Local config file or remote URL for installation.
	-a <value>          Override auto_discovery_key.
	-t <value>          Override token.
	-e <url>            Override endpoint URL http(s).
	-log                Tail service status and last 50 log lines in real time.
	--auto [min|d]      Enable auto config updates (default 10 min) or disable with 'd'.
	--debug             Enable verbose execution trace.
	-u, --uninstall     Stop services/cron and remove installation directory.

Examples:
	bash ${SCRIPT_BASENAME} -c ./config.json
	bash ${SCRIPT_BASENAME} -a KEY -e URL
	bash ${SCRIPT_BASENAME} -t TOKEN -e URL
	bash ${SCRIPT_BASENAME} -c http(s)://example.com/config.json --auto 10

EOF
}

install_packages() {
	local commands=("$@")
	local missing=()
	for cmd in "${commands[@]}"; do
		if ! command -v "${cmd}" >/dev/null 2>&1; then
			missing+=("${cmd}")
		fi
	done
	[[ ${#missing[@]} -eq 0 ]] && return 0

	local pm=""
	if command -v apt-get >/dev/null 2>&1; then
		pm="apt-get"
	elif command -v apt >/dev/null 2>&1; then
		pm="apt"
	elif command -v dnf >/dev/null 2>&1; then
		pm="dnf"
	elif command -v yum >/dev/null 2>&1; then
		pm="yum"
	elif command -v apk >/dev/null 2>&1; then
		pm="apk"
	else
		die "Unsupported package manager. Please install ${missing[*]} manually."
	fi

	local packages=()
	for cmd in "${missing[@]}"; do
		case ${cmd} in
			crontab)
				case ${pm} in
					apt-get|apt)
						packages+=("cron")
						;;
					dnf|yum)
						packages+=("cronie")
						;;
					apk)
						packages+=("dcron")
						;;
					*)
						packages+=("${cmd}")
						;;
				esac
				;;
			*)
				packages+=("${cmd}")
				;;
		esac
	done

	local unique_packages=()
	declare -A seen=()
	for pkg in "${packages[@]}"; do
		if [[ -z ${seen[${pkg}]+x} ]]; then
			unique_packages+=("${pkg}")
			seen[${pkg}]=1
		fi
	done

	log_info "Installing missing dependencies (${missing[*]}) via ${pm}"
	case ${pm} in
		apt-get)
			sudo apt-get update || die "Failed to update package index using apt-get"
			sudo apt-get install -y "${unique_packages[@]}" || die "Failed to install packages: ${unique_packages[*]}"
			;;
		apt)
			sudo apt update || die "Failed to update package index using apt"
			sudo apt install -y "${unique_packages[@]}" || die "Failed to install packages: ${unique_packages[*]}"
			;;
		dnf)
			sudo dnf makecache || die "Failed to update package index using dnf"
			sudo dnf install -y "${unique_packages[@]}" || die "Failed to install packages: ${unique_packages[*]}"
			;;
		yum)
			sudo yum makecache || die "Failed to update package index using yum"
			sudo yum install -y "${unique_packages[@]}" || die "Failed to install packages: ${unique_packages[*]}"
			;;
		apk)
			sudo apk update || die "Failed to update package index using apk"
			sudo apk add "${unique_packages[@]}" || die "Failed to install packages: ${unique_packages[*]}"
			;;
		*)
			die "Unsupported package manager. Please install ${missing[*]} manually."
			;;
	esac
}

enable_crond_on_alpine() {
	if running_on_alpine; then
		log_info "Ensuring crond is enabled on Alpine"
		if ! sudo rc-service crond start; then
			log_warn "Failed to start crond automatically. Please start it manually."
		fi
		if ! sudo rc-update add crond >/dev/null 2>&1; then
			log_warn "Failed to add crond to rc-update."
		fi
	fi
}

ensure_linger() {
	if running_on_systemd; then
		if ! command -v loginctl >/dev/null 2>&1; then
			log_warn "loginctl not found; linger will not be adjusted"
			return
		fi
		if ! sudo loginctl enable-linger "${USER}" >/dev/null 2>&1; then
			log_warn "loginctl enable-linger failed. User services may not start on boot."
		else
			log_success "linger enabled for ${USER}"
		fi
	fi
}

validate_alnum() {
	local value=$1
	[[ ${#value} -le 64 && ${value} =~ ^[0-9A-Za-z]+$ ]]
}

validate_url() {
	local url=$1
	if [[ ! ${url} =~ ^https?:// ]]; then
		return 1
	fi
	if ! curl -Is --max-time 10 "${url}" >/dev/null; then
		return 1
	fi
	return 0
}

validate_json_file() {
	local file=$1
	if command -v jq >/dev/null 2>&1; then
		if ! jq empty "${file}" >/dev/null 2>&1; then
			die "Config ${file} is not valid JSON"
		fi
	elif command -v python3 >/dev/null 2>&1; then
		if ! python3 -m json.tool "${file}" >/dev/null 2>&1; then
			die "Config ${file} is not valid JSON"
		fi
	else
		log_warn "Skipping JSON validation; jq and python3 not available"
	fi
}

fetch_config_from_source() {
	local source=$1
	local dest=$2
	if [[ -z ${source} ]]; then
		printf '%s\n' "${DEFAULT_CONFIG_TEMPLATE}" >"${dest}"
		return
	fi

	if [[ -f ${source} ]]; then
		cp "${source}" "${dest}"
	else
		curl -fsSL "${source}" -o "${dest}" || die "Failed to download config from ${source}"
	fi
}

apply_config_override() {
	local key=$1
	local value=$2
	local file=$3

	if command -v jq >/dev/null 2>&1; then
		local tmp_file
		tmp_file=$(mktemp)
		jq --arg v "${value}" ".${key} = \$v" "${file}" >"${tmp_file}" && mv "${tmp_file}" "${file}"
	else
		python3 - <<PY
import json,sys
path = "${file}"
key = "${key}"
value = "${value}"
with open(path, 'r', encoding='utf-8') as fh:
		data = json.load(fh)
data[key] = value
with open(path, 'w', encoding='utf-8') as fh:
		json.dump(data, fh, ensure_ascii=False, indent=2)
PY
	fi
}

current_arch_url() {
	local arch
	arch=$(uname -m)
	case "${arch}" in
		x86_64|amd64)
			printf '%s' "${AMD64_URL}"
			;;
		aarch64|arm64)
			printf '%s' "${ARM64_URL}"
			;;
		*)
			die "Unsupported architecture: ${arch}"
			;;
	esac
}

download_agent_binary() {
	local url
	url=$(current_arch_url)
	log_info "Downloading komari-agent binary from ${url}"
	mkdir -p "$(dirname "${BIN_PATH}")"
	curl -fsSL "${url}" -o "${BIN_PATH}" || die "Failed to download komari-agent binary"
	chmod +x "${BIN_PATH}"
	log_success "Binary placed at ${BIN_PATH}"
}

generate_wrapper_script() {
	cat >"${RUN_DIR}/komari-wrapper.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${HOME}/.local/komari-agent"
BIN_PATH="${INSTALL_DIR}/bin/komari-agent"
CONFIG_PATH="${INSTALL_DIR}/config.json"
LOG_DIR="${INSTALL_DIR}/logs"
RUN_DIR="${INSTALL_DIR}/run"
AUTO_CONF="${RUN_DIR}/auto-update.conf"
UPDATE_SCRIPT="${RUN_DIR}/update-config.sh"
UPDATED_FLAG="${RUN_DIR}/.config_updated"
AGENT_LOG="${LOG_DIR}/komari-agent.log"

mkdir -p "${LOG_DIR}"

agent_pid=0

cleanup() {
	if [[ ${agent_pid:-0} -ne 0 ]]; then
		kill "${agent_pid}" 2>/dev/null || true
		wait "${agent_pid}" 2>/dev/null || true
		agent_pid=0
	fi
}

trap 'cleanup; exit 0' INT TERM
trap cleanup EXIT

read_auto_conf() {
	AUTO_ENABLED=0
	AUTO_INTERVAL=10
	AUTO_URL=""
	if [[ -f ${AUTO_CONF} ]]; then
		# shellcheck disable=SC1090
		source "${AUTO_CONF}"
	fi
	if [[ -z ${AUTO_INTERVAL} || ! ${AUTO_INTERVAL} =~ ^[0-9]+$ ]]; then
		AUTO_INTERVAL=10
	elif (( AUTO_INTERVAL <= 0 )); then
		AUTO_INTERVAL=10
	fi
}

ensure_update_script() {
	cat >"${UPDATE_SCRIPT}" <<'US'
#!/usr/bin/env bash
set -euo pipefail

RUN_DIR="${HOME}/.local/komari-agent/run"
AUTO_CONF="${RUN_DIR}/auto-update.conf"
CONFIG_PATH="${HOME}/.local/komari-agent/config.json"
UPDATED_FLAG="${RUN_DIR}/.config_updated"
TMP_FILE="$(mktemp)"

AUTO_ENABLED=0
AUTO_INTERVAL=10
AUTO_URL=""
if [[ -f ${AUTO_CONF} ]]; then
	# shellcheck disable=SC1090
	source "${AUTO_CONF}"
fi

if [[ ${AUTO_ENABLED} -ne 1 || -z ${AUTO_URL} ]]; then
	rm -f "${TMP_FILE}"
	exit 0
fi

if ! curl -fsSL "${AUTO_URL}" -o "${TMP_FILE}"; then
	rm -f "${TMP_FILE}"
	exit 0
fi

if [[ ! -f ${CONFIG_PATH} ]]; then
	mv "${TMP_FILE}" "${CONFIG_PATH}"
	touch "${UPDATED_FLAG}"
	exit 0
fi

current_hash=$(sha256sum "${CONFIG_PATH}" | awk '{print $1}')
new_hash=$(sha256sum "${TMP_FILE}" | awk '{print $1}')

if [[ ${current_hash} != ${new_hash} ]]; then
	mv "${TMP_FILE}" "${CONFIG_PATH}"
	touch "${UPDATED_FLAG}"
else
	rm -f "${TMP_FILE}"
fi
US
	chmod +x "${UPDATE_SCRIPT}"
}

main_loop() {
	ensure_update_script
	read_auto_conf
	local last_update=0
	local last_hash=""
	if [[ -f ${CONFIG_PATH} ]]; then
		last_hash=$(sha256sum "${CONFIG_PATH}" | awk '{print $1}')
	fi
	while true; do
		read_auto_conf
		local now
		now=$(date +%s)
		local interval=$((AUTO_INTERVAL * 60))
		if (( interval <= 0 )); then
			interval=600
		fi
		if [[ ${AUTO_ENABLED} -eq 1 ]]; then
			if (( now - last_update >= interval )); then
				"${UPDATE_SCRIPT}" || true
				last_update=${now}
			fi
		fi
		if [[ -f ${UPDATED_FLAG} ]]; then
			rm -f "${UPDATED_FLAG}"
			if [[ -f ${CONFIG_PATH} ]]; then
				last_hash=$(sha256sum "${CONFIG_PATH}" | awk '{print $1}')
			else
				last_hash=""
			fi
			cleanup
		fi
		if [[ -f ${CONFIG_PATH} ]]; then
			local current_hash
			current_hash=$(sha256sum "${CONFIG_PATH}" | awk '{print $1}')
			if [[ ${current_hash} != ${last_hash} ]]; then
				last_hash=${current_hash}
				cleanup
			fi
		fi
		if [[ ${agent_pid:-0} -eq 0 ]]; then
			if [[ -x ${BIN_PATH} && -f ${CONFIG_PATH} ]]; then
				"${BIN_PATH}" --config "${CONFIG_PATH}" >>"${AGENT_LOG}" 2>&1 &
				agent_pid=$!
			else
				sleep 5
				continue
			fi
		elif ! kill -0 "${agent_pid}" 2>/dev/null; then
			wait "${agent_pid}" 2>/dev/null || true
			agent_pid=0
		fi
		sleep 5
		done
}

main_loop
EOF
	chmod +x "${RUN_DIR}/komari-wrapper.sh"
}

write_auto_conf() {
	local enabled=$1
	local interval=$2
	local url=$3
	{
		printf 'AUTO_ENABLED=%s\n' "${enabled}"
		printf 'AUTO_INTERVAL=%s\n' "${interval}"
		printf 'AUTO_URL=%q\n' "${url}"
	} >"${RUN_DIR}/auto-update.conf"
}

setup_systemd_service() {
	mkdir -p "${HOME}/.config/systemd/user"
	cat >"${SYSTEMD_UNIT_PATH}" <<EOF
[Unit]
Description=Komari Agent (user scope)
After=network-online.target

[Service]
Type=simple
ExecStart=${RUN_DIR}/komari-wrapper.sh
Restart=always
RestartSec=5
Environment=DEBUG=${DEBUG_MODE}

[Install]
WantedBy=default.target
EOF

	if ! command -v systemctl >/dev/null 2>&1; then
		log_warn "systemctl not available; start ${SERVICE_NAME} manually"
		return
	fi

	systemctl --user daemon-reload
	if systemctl --user enable --now "${SERVICE_NAME}"; then
		log_success "systemd user service ${SERVICE_NAME} active"
	else
		log_warn "Failed to enable systemd user service"
	fi
}

setup_alpine_cron() {
	local interval=10
	if [[ -f ${RUN_DIR}/auto-update.conf ]]; then
		local AUTO_ENABLED AUTO_INTERVAL AUTO_URL
		# shellcheck disable=SC1090
		source "${RUN_DIR}/auto-update.conf"
		if [[ ${AUTO_INTERVAL:-} =~ ^[0-9]+$ && ${AUTO_INTERVAL} -gt 0 ]]; then
			interval=${AUTO_INTERVAL}
		fi
	fi
	if (( interval <= 0 )); then
		interval=10
	fi
	if (( interval > 59 )); then
		interval=59
	fi
	local schedule="*/${interval}"

	local cron_file
	cron_file=$(mktemp)
	if crontab -l 2>/dev/null | grep -v "${RUN_DIR}/komari-cron-wrapper.sh" >"${cron_file}"; then
		:
	else
		: >"${cron_file}"
	fi
	{
		echo "@reboot ${RUN_DIR}/komari-cron-wrapper.sh"
		echo "${schedule} * * * * ${RUN_DIR}/komari-cron-wrapper.sh --tick"
	} >>"${cron_file}"
	crontab "${cron_file}"
	rm -f "${cron_file}"
	cat >"${RUN_DIR}/komari-cron-wrapper.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

RUN_DIR="${HOME}/.local/komari-agent/run"
WRAPPER="${RUN_DIR}/komari-wrapper.sh"

if [[ ${1-} == "--tick" ]]; then
	"${RUN_DIR}/update-config.sh" || true
	exit 0
fi

	if command -v pgrep >/dev/null 2>&1; then
		if ! pgrep -f "${WRAPPER}" >/dev/null 2>&1; then
			nohup "${WRAPPER}" >/dev/null 2>&1 &
		fi
	else
		if ! ps -ef | grep -F "${WRAPPER}" | grep -v grep >/dev/null 2>&1; then
			nohup "${WRAPPER}" >/dev/null 2>&1 &
		fi
	fi
EOF
	chmod +x "${RUN_DIR}/komari-cron-wrapper.sh"
	touch "${ALPINE_CRON_MARKER}"
	nohup "${RUN_DIR}/komari-cron-wrapper.sh" >/dev/null 2>&1 &
	log_success "cron-based supervision installed (interval ${interval} min)"
}

render_log_tail() {
	if running_on_systemd && command -v systemctl >/dev/null 2>&1; then
		systemctl --user status "${SERVICE_NAME}" --no-pager || true
		journalctl --user-unit "${SERVICE_NAME}" -n 50 -f
	else
		if [[ -f ${LOG_DIR}/komari-agent.log ]]; then
			tail -n 50 -f "${LOG_DIR}/komari-agent.log"
		else
			die "Log file not found"
		fi
	fi
}

uninstall_all() {
	log_info "Stopping komari-agent services"
	if running_on_systemd; then
		systemctl --user stop "${SERVICE_NAME}" || true
		systemctl --user disable "${SERVICE_NAME}" || true
		rm -f "${SYSTEMD_UNIT_PATH}"
		systemctl --user daemon-reload || true
	fi
	if running_on_alpine && [[ -f ${ALPINE_CRON_MARKER} ]]; then
		local cron_file
		cron_file=$(mktemp)
		if crontab -l 2>/dev/null | grep -v "${RUN_DIR}/komari-cron-wrapper.sh" >"${cron_file}"; then
			crontab "${cron_file}" || true
		else
			crontab -r 2>/dev/null || true
		fi
		rm -f "${cron_file}" "${ALPINE_CRON_MARKER}"
	fi
	rm -rf "${INSTALL_DIR}"
	log_success "komari-agent uninstalled"
}

is_installed() {
	[[ -x ${BIN_PATH} ]]
}

# -----------------------------
# Argument parsing
# -----------------------------

POSITIONAL=()
while [[ $# -gt 0 ]]; do
	case $1 in
		-c)
			[[ $# -ge 2 ]] || die "-c requires a value"
			CFG_SOURCE=$2
			shift 2
			;;
		-a)
			[[ $# -ge 2 ]] || die "-a requires a value"
			OPT_AUTO_DISCOVERY=$2
			shift 2
			;;
		-t)
			[[ $# -ge 2 ]] || die "-t requires a value"
			OPT_TOKEN=$2
			shift 2
			;;
		-e)
			[[ $# -ge 2 ]] || die "-e requires a value"
			OPT_ENDPOINT=$2
			shift 2
			;;
		-log)
			SHOW_LOGS=1
			shift
			;;
		--auto)
			if [[ $# -ge 2 && $2 != -* ]]; then
				AUTO_MODE=$2
				shift 2
			else
				AUTO_MODE=10
				shift
			fi
			;;
		--debug)
			DEBUG_MODE=1
			shift
			;;
		-u|--uninstall)
			UNINSTALL_ONLY=1
			shift
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			POSITIONAL+=("$1")
			shift
			;;
	esac
done

set -- "${POSITIONAL[@]}"

if [[ ${DEBUG_MODE} -eq 1 ]]; then
	set -x
fi

if [[ ${#POSITIONAL[@]} -gt 0 ]]; then
	log_warn "Ignoring unexpected positional arguments: ${POSITIONAL[*]}"
fi

if [[ ${UNINSTALL_ONLY} -eq 1 ]]; then
	uninstall_all
	exit 0
fi

if [[ ${SHOW_LOGS} -eq 1 ]]; then
	render_log_tail
	exit 0
fi

install_packages curl
if ! command -v sha256sum >/dev/null 2>&1; then
	die "sha256sum command not found. Please install coreutils or equivalent."
fi
if ! command -v jq >/dev/null 2>&1; then
	install_packages jq
fi
if ! running_on_systemd; then
	install_packages crontab
fi
enable_crond_on_alpine

# Validate inputs
VALID_COMBO=0

if [[ -n ${CFG_SOURCE} ]]; then
	VALID_COMBO=1
	if [[ -f ${CFG_SOURCE} ]]; then
		CFG_URL_FOR_AUTO=""
	else
		validate_url "${CFG_SOURCE}" || die "-c URL is not reachable"
		CFG_URL_FOR_AUTO="${CFG_SOURCE}"
	fi
fi

if [[ -n ${OPT_AUTO_DISCOVERY} || -n ${OPT_TOKEN} ]]; then
	[[ -n ${OPT_ENDPOINT} ]] || die "-e must be supplied when using -a or -t"
	validate_url "${OPT_ENDPOINT}" || die "Invalid endpoint URL"
fi

if [[ -n ${OPT_AUTO_DISCOVERY} ]]; then
	validate_alnum "${OPT_AUTO_DISCOVERY}" || die "-a value must be alphanumeric <=64 chars"
	VALID_COMBO=1
fi

if [[ -n ${OPT_TOKEN} ]]; then
	validate_alnum "${OPT_TOKEN}" || die "-t value must be alphanumeric <=64 chars"
	VALID_COMBO=1
fi

if [[ -n ${OPT_ENDPOINT} ]]; then
	VALID_COMBO=1
fi

if [[ ${VALID_COMBO} -eq 0 ]]; then
	die "Installation requires -c or (-a & -e) or (-t & -e)."
fi

ensure_dirs

if is_installed; then
	log_warn "komari-agent already installed at ${INSTALL_DIR}. Use -u to uninstall or -log to inspect logs."
	exit 0
fi

fetch_config_from_source "${CFG_SOURCE}" "${CONFIG_PATH}"

if [[ -n ${OPT_AUTO_DISCOVERY} ]]; then
	apply_config_override "auto_discovery_key" "${OPT_AUTO_DISCOVERY}" "${CONFIG_PATH}"
fi
if [[ -n ${OPT_TOKEN} ]]; then
	apply_config_override "token" "${OPT_TOKEN}" "${CONFIG_PATH}"
fi
if [[ -n ${OPT_ENDPOINT} ]]; then
	apply_config_override "endpoint" "${OPT_ENDPOINT}" "${CONFIG_PATH}"
fi

validate_json_file "${CONFIG_PATH}"
chmod 600 "${CONFIG_PATH}"

download_agent_binary
generate_wrapper_script

AUTO_ENABLED=0
AUTO_INTERVAL=10
AUTO_URL="${CFG_URL_FOR_AUTO}"

if [[ -n ${AUTO_MODE} ]]; then
	AUTO_MODE=$(printf '%s' "${AUTO_MODE}" | tr '[:upper:]' '[:lower:]')
	if [[ ${AUTO_MODE} == d ]]; then
		AUTO_ENABLED=0
	else
		if [[ ${AUTO_MODE} =~ ^[0-9]+$ ]]; then
			if (( AUTO_MODE == 0 )); then
				die "--auto value must be greater than 0"
			fi
			AUTO_ENABLED=1
			AUTO_INTERVAL=${AUTO_MODE}
			if [[ -z ${AUTO_URL} ]]; then
				die "--auto requires a remote URL source provided via -c"
			fi
		else
			die "Invalid value for --auto"
		fi
	fi
fi

write_auto_conf "${AUTO_ENABLED}" "${AUTO_INTERVAL}" "${AUTO_URL}"

ensure_linger

if running_on_systemd; then
	setup_systemd_service
else
	setup_alpine_cron
fi

if [[ ${AUTO_ENABLED} -eq 1 ]]; then
	log_info "Auto config updates enabled every ${AUTO_INTERVAL} minute(s) from ${AUTO_URL}"
else
	log_info "Auto config updates disabled"
fi

log_success "komari-agent installation complete"

