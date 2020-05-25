#!/bin/bash -e

# Helper script for osmo-remsim-client-st2 on OWHW hardware. It performs the hardware-specific
# functions required by remsim-client.

# environment variables available:
#	REMSIM_CLIENT_VERSION
#	REMSIM_SERVER_ADDR
#	REMSIM_SERVER_STATE
#	REMSIM_BANKD_ADDR
#	REMSIM_BANKD_STATE
#	REMSIM_CLIENT_SLOT
#	REMSIM_BANKD_SLOT
#	REMSIM_SIM_VCC
#	REMSIM_SIM_RST
#	REMSIM_CAUSE
#	REMSIM_USB_PATH
#	REMSIM_USB_INTERFACE

CAUSE="$1"

# derive the modem (1/2) from the USB interface of the SIMTRACE2 firmware (0/1)
case "${REMSIM_USB_INTERFACE}" in
	0)
		MODEM=1
		;;
	1)
		MODEM=2
		;;
	*)
		echo "Unknown REMSIM_USB_INTERFACE ${REMSIM_USB_INTERFACE}"
		exit 1
		;;
esac



case "${CAUSE}" in
	event-server-connect)
		;;
	event-bankd-connect)
		;;
	event-config-bankd)
		;;
	event-modem-status)
		;;
	request-card-insert)
		echo "Enabling Remote SIM for ${MODEM}"
		echo -n "1" > "/dev/gpio/connect_st_usim${MODEM}/value"
		;;
	request-card-remove)
		echo "Disabling Remote SIM for ${MODEM}"
		echo -n "0" > "/dev/gpio/connect_st_usim${MODEM}/value"
		;;
	request-modem-reset)
		echo "Resetting Modem ${MODEM}"
		echo -n "1" > "/dev/gpio/mdm${MODEM}_rst/value"
		sleep 1
		echo -n "0" > "/dev/gpio/mdm${MODEM}_rst/value"
		# for v5 no effect on v4
		case "${MODEM}" in
			1)
				gpioset gpiochip6 1=1
				sleep 1
				gpioset gpiochip6 1=0
				;;
			2)
				gpioset gpiochip6 3=1
				sleep 1
				gpioset gpiochip6 3=0
				;;
		esac
		;;
	request-sim-remote)
		;;
	*)
		echo "Unknown CAUSE ${CAUSE}: ignoring"
		;;
esac
