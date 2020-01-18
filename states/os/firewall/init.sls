#!pyobjects

from salt://os/firewall/objects.sls import Firewall, Table, Chain, Rule, log

firewall = Firewall.from_data(pillar('firewall', {}))

SERVICE_NAME = 'netfilter-persistent'

with Pkg.latest('iptables', pkgs=['iptables', 'iptables-persistent']):
    File.managed('rules.v4',
                 name='/etc/iptables/rules.v4',
                 contents=firewall.render(4))
    File.managed('rules.v6',
                 name='/etc/iptables/rules.v6',
                 contents=firewall.render(6))

    if firewall.config.get('apply', True):
        Service.running(SERVICE_NAME,
                        enable=True,
                        restart=True,
                        watch=[File('rules.v4'),
                               File('rules.v6')])
        if 'services.ipsec' in pillar('__reclass__:applications'):
            Module.wait('service.restart',
                        m_name='strongswan',
                        watch=[Service(SERVICE_NAME)])
    else:
        Service.disabled(SERVICE_NAME)
