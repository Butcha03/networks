from scapy.all import traceroute
import ipwhois
import ipaddress

def get_asn(ip):
    if ipaddress.ip_address(ip).is_private:
        return "Private IP", "N/A", "N/A", "N/A"
    
    obj = ipwhois.IPWhois(ip)
    data = obj.lookup_rdap()
    asn = data.get('asn', 'N/A')
    info = data.get('asn_description', 'N/A')
    country = data.get('asn_country_code', 'N/A')
    provider_info = data.get('network', {})
    provider = f"{provider_info.get('name', 'N/A')}"
    return asn, info, country, provider

def trace_autonomous_system(target):
    ans, unans = traceroute(target, maxttl=30)
    seen_ips = set()
    for snd, rcv in ans.res:
        ip = rcv.src
        if ip not in seen_ips:
            seen_ips.add(ip)
            asn, info, country, provider = get_asn(ip)
            print(f"IP: {ip}")
            print(f"AS Number: {asn}")
            print(f"Information: {info}")
            print(f"Country: {country}")
            print(f"Provider: {provider}")
            print("")

if __name__ == "__main__":
    target = input("Введите доменное имя или IP адрес для трассировки: ")
    trace_autonomous_system(target)
