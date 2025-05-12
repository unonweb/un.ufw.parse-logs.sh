function isValidIP() {
  local ip="${1}"
  # Use a regular expression to validate the IP address
  if [[ "${ip}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
      # Split the IP into its components
      IFS='.' read -r i1 i2 i3 i4 <<< "$ip"
      # Check if each component is between 0 and 255
      if (( i1 >= 0 && i1 <= 255 )) && (( i2 >= 0 && i2 <= 255 )) && (( i3 >= 0 && i3 <= 255 )) && (( i4 >= 0 && i4 <= 255 )); then
          #echo "Valid IP address"
          return 0
      fi
  fi
  #echo "Invalid IP address"
  return 1
}