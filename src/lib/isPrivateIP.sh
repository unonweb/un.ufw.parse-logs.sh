function isPrivateIP() { # ${ip}
	local ip=${1}

	[[ -z "${ip}" ]] && return 1
	[[ ${ip} =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|169\.254\.) ]] && return 0
	return 1
}