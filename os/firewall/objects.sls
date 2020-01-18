#!pyobjects

import logging
import re

log = logging.getLogger('salt.pyobjects.firewall')

v6_local = re.compile(r'^(?!(fe80|fc00|::1$))')
v4_local = re.compile(r'^(?!(10\.20|172\.(1[6-9]|2[0-9]|3[0-1])|127\.))')

class Firewall:
    DEFAULTS = {
        'nat': [
            'prerouting',
            'output',
            'postrouting',
        ],
        'mangle': [
            'prerouting',
            'input',
            'forward',
            'output',
            'postrouting',
        ],
        'filter': [
            'forward',
            'input',
            'output',
        ],
    }

    @staticmethod
    def from_data(data):
        config = data.pop('config', {})
        firewall = Firewall(config)
        for table, chains in data.items():
            for chain, rules in chains.items():
                chain = firewall.table(table).chain(chain)
                chain.set_defaults(**rules.pop('_defaults', {}))
                for comment, rule in rules.items():
                    if rule is False:
                        continue
                    log.info('Adding rule %s %s', comment, rule)
                    chain.add_rule(comment, **rule)
        return firewall

    def __init__(self, config):
        self.config = {'apply': True}
        self.config.update(config)
        self.tables = {}
        for table, chains in self.DEFAULTS.items():
            for chain in chains:
                self.table(table).chain(chain)

    def table(self, name):
        if name in self.tables:
            return self.tables[name]
        table = Table(self, name)
        self.tables[name] = table
        return table

    def __render(self, version=4):
        for table in self.tables.values():
            yield str(table)
            for chain in table.chains.values():
                yield str(chain)
            for chain in table.chains.values():
                for rule in chain.rules:
                    yield rule.render(version)
            yield 'COMMIT'

    def render(self, version=4):
        return '\n'.join(self.__render(version))


class Table:
    def __init__(self, firewall, name):
        self.firewall = firewall
        self.name = name
        self.chains = {}

    def __str__(self):
        return '*' + self.name

    def chain(self, name):
        if name in self.chains:
            return self.chains[name]
        chain = Chain(self, name)
        self.chains[name] = chain
        return chain


class Chain:
    def __init__(self, table, name):
        self.table = table
        self.name = name.upper()
        self._rules = []
        self.chain_jump = 'ACCEPT'
        self.rule_jump = None
        self.rule_jump_args = {}

    def __str__(self):
        return ':{} {} [0:0]'.format(self.name, self.chain_jump)

    def __len__(self):
        return len(self._rules)

    @property
    def rules(self):
        return sorted(self._rules, key=lambda rule: rule.priority)

    def set_defaults(self, chain=None, jump=None, jump_args=None):
        if chain:
            self.chain_jump = chain
        if jump:
            self.rule_jump = jump
        if jump_args:
            self.rule_jump_args.update(jump_args)

    def add_rule(self, comment, **kwargs):
        rule = Rule(self, comment, **kwargs)
        self._rules.append(rule)
        return rule


class Rule:
    ARG_ABBR = {
        'in': '-i',
        'not_in': '! -i',
        'out': '-o',
        'not_out': '! -o',
        'src': '-s',
        'not_src': '! -s',
        'dest': '-d',
        'not_dest': '! -d',
    }

    def __init__(self,
                 chain,
                 comment,
                 proto=None,
                 module=None,
                 jump=None,
                 jump_args={},
                 _version=None,
                 _priority=1000,
                 **kwargs):
        self.comment = comment
        self.chain = chain
        self.proto = proto
        self.module = module
        self.jump = jump
        self.jump_args = jump_args
        self.version = _version
        self.priority = _priority
        self.kwargs = kwargs

    def __replace_local(self, kwargs, name, version):
        if name in kwargs and kwargs[name] == '$local':
            kwargs[name] = list(filter(v6_local.match, filter(v4_local.match, grains('ipv{}'.format(version)))))

    def __join_multi(self, kwargs, name):
        if name in kwargs:
            val = kwargs[name]
            if isinstance(val, list):
                val = ','.join(val)
                kwargs[name] = val

    def __render(self, kwargs, proto=None):
        args = ['-A', self.chain.name]
        if proto:
            args.extend(('-p', proto))
        if self.module:
            args.extend(('-m', self.module))
        for key, val in kwargs.items():
            args.extend((self.ARG_ABBR.get(key, '--' + key),
                         str(val)))
        args.extend(('-j', self.jump or self.chain.rule_jump))
        jump_args = self.chain.rule_jump_args.copy()
        jump_args.update(self.jump_args)
        for key, val in jump_args.items():
            args.extend(('--' + key, str(val)))

        args.extend(('-m comment --comment', '"salt: {}"'.format(self.comment)))
        log.info('%r', args)
        return ' '.join(args)

    def render(self, version):
        if self.version and self.version != version:
            return ''
        kwargs = self.kwargs.copy()
        self.__replace_local(kwargs, 'src', version)
        self.__replace_local(kwargs, 'dest', version)
        self.__join_multi(kwargs, 'src')
        self.__join_multi(kwargs, 'dest')

        out = ['# ' + self.comment]
        try:
            if isinstance(self.proto, list):
                out.extend(self.__render(kwargs, proto) for proto in self.proto)
            else:
                out.append(self.__render(kwargs, self.proto))
        except:
            log.error(
                "Error rendering %r /* %s */",
                self.chain,
                self.comment)
            raise
        return '\n'.join(out)
