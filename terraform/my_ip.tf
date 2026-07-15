# Auto-detect the caller's public IP when var.my_ip is left unset, so
# nobody has to hardcode/update an IP address by hand (it drifts whenever a
# VPN toggles or someone else runs apply from a different network). An
# explicit var.my_ip still wins when set.

data "http" "my_ip" {
  count = var.my_ip == "" ? 1 : 0

  url = "https://ifconfig.me/ip"
  request_headers = {
    "User-Agent" = "curl/8.0"
  }
}

locals {
  raw_my_ip = var.my_ip != "" ? chomp(var.my_ip) : chomp(data.http.my_ip[0].response_body)

  # Keep an explicit CIDR as-is. If it's a bare IP, normalize to a single-host
  # CIDR: /32 for IPv4, /128 for IPv6.
  my_ip = can(cidrhost(local.raw_my_ip, 0)) ? local.raw_my_ip : (
    strcontains(local.raw_my_ip, ":") ? "${local.raw_my_ip}/128" : "${local.raw_my_ip}/32"
  )
}
