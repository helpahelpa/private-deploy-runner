"""Opt-in pinned admin relay lifecycle; no host listeners or source commands."""
from contextlib import contextmanager
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import time
from urllib.parse import urlsplit


def require(value,message):
    if not value:raise ValueError(message)


def checksum(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class AdminRuntime:
    def __init__(self,engine):
        self.engine=engine;self.config=engine.c.get('admin_runtime');self.modes={};self.pins={};self.deadline=None;self.egress=None
        self.name=engine.c['project']+'-admin-relay'
        if self.config is None:return
        c=self.config
        required={'state_volume','log_volume','environment','relay_image','edge_origin','relay_secret_file','routes_file'}
        require(isinstance(c,dict) and required<=set(c) and set(c)<=required|{'upstream_proxy','origin_server_name','egress_identity_file'},'Invalid optional admin runtime configuration')
        for key in ('state_volume','log_volume'):
            require(isinstance(c[key],str) and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}',c[key]),'Invalid admin volume')
        require(len({c['state_volume'],c['log_volume'],engine.c['data_volume']})==3,'Admin, logs and world volumes must differ')
        require(isinstance(c['environment'],str) and re.fullmatch(r'[a-z][a-z0-9_-]{0,31}',c['environment']),'Invalid admin environment')
        require(isinstance(c['relay_image'],str) and re.fullmatch(r'sha256:[0-9a-f]{64}',c['relay_image']),'Pinned admin relay image required')
        origin=urlsplit(c['edge_origin']);host=origin.hostname
        require(origin.scheme=='https' and origin.port in (None,443) and not origin.username and not origin.password
                and origin.path in ('','/') and not origin.query and not origin.fragment and host
                and re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?',host),'Canonical HTTPS admin edge required')
        try:ipaddress.ip_address(host)
        except ValueError:pass
        else:raise ValueError('Admin edge must use a hostname')
        require(c.get('origin_server_name','localhost')=='localhost','Admin TLS name must remain localhost')
        if c.get('upstream_proxy'):
            proxy=urlsplit(c['upstream_proxy'])
            require(proxy.scheme=='socks5' and proxy.hostname and proxy.port and 1<=proxy.port<=65535
                    and not proxy.username and not proxy.password and proxy.path in ('','/')
                    and not proxy.query and not proxy.fragment,'Credential-free fixed SOCKS5 proxy required')
        for key in ('relay_secret_file','routes_file'):
            raw=Path(c[key]);path=raw if raw.is_absolute() else engine.config_path.parent/raw
            require(not path.is_symlink() and path.is_file() and not re.search(r'[,\x00-\x1f\x7f]',str(path)),'Private admin file missing or unsafe')
            path=path.resolve();require(path.stat().st_size<=1024*1024,'Oversized admin runtime file');c[key]=str(path)
            self.pins[str(path)]=checksum(path)
        secret=Path(c['relay_secret_file'])
        require(not secret.stat().st_mode&0o077 and 32<=len(secret.read_text().strip())<=256,'Private relay secret permissions or length invalid')
        routes=json.loads(Path(c['routes_file']).read_text());require(isinstance(routes,list) and 0<len(routes)<=1000,'Invalid admin route policy')
        self.egress=None
        if c.get('egress_identity_file'):
            path=Path(c['egress_identity_file'])
            if not path.is_absolute():path=engine.config_path.parent/path
            require(not path.is_symlink() and path.is_file() and path.stat().st_size<=65536,'Private egress identity missing')
            path=path.resolve();self.pins[str(path)]=checksum(path);c['egress_identity_file']=str(path)
            self.egress=json.loads(path.read_text());spec=self.egress
            require(isinstance(spec,dict) and spec.get('internal_network')==engine.network
                    and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}',spec.get('name',''))
                    and re.fullmatch(r'sha256:[0-9a-f]{64}',spec.get('image',''))
                    and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}',spec.get('egress_network',''))
                    and spec['egress_network']!=engine.network,'Invalid pinned egress identity')
            proxy=urlsplit(c.get('upstream_proxy',''))
            require(proxy.hostname==spec.get('alias') and proxy.port==spec.get('port'),'Egress proxy identity mismatch')
            command=spec.get('fixed_command');require(isinstance(command,list) and len(command)%2==0,'Invalid fixed egress command')
            options=dict(zip(command[::2],command[1::2]))
            require(len(options)*2==len(command) and set(options)<={'--bind-ip','--port','--allowed-host','--upstream-host','--upstream-port'}
                    and options.get('--allowed-host')==host and options.get('--bind-ip')==spec.get('bind_ip')
                    and options.get('--port')==str(spec.get('port')),'Egress destination/bind policy mismatch')


    @contextmanager
    def bounded(self,deadline):
        previous=self.deadline
        self.deadline=min(previous,deadline) if previous and deadline else previous or deadline
        try:yield
        finally:self.deadline=previous

    def docker(self,*args,timeout=30):
        if self.deadline:
            remaining=self.deadline-time.monotonic()
            require(remaining>0,'Admin runtime deadline expired')
            timeout=min(timeout,remaining)
        return self.engine.docker(*args,timeout=timeout)

    def inspect(self,cid):
        require(re.fullmatch(r'[0-9a-f]{64}',cid or ''),'Exact admin container identity required')
        return json.loads(self.docker('inspect',cid))[0]

    def enabled(self,cid=None):
        if self.config is None:return False
        if cid is None:return True
        if cid in self.modes:return self.modes[cid]
        registry=self.engine.root/'active.json'
        if registry.is_file():
            active=json.loads(registry.read_text())
            if active.get('container')==cid:return active.get('admin_enabled') is True
        return True

    def supported(self,release):
        info=json.loads((Path(release)/'server.json').read_text())
        return {'server/admin_api.py','server/admin_store.py','server/server_logs.py'}<=set(info.get('source_files',{}))

    def validate_egress(self):
        if self.egress is None:return
        spec=self.egress;data=json.loads(self.docker('inspect',spec['name']))[0];h,c=data['HostConfig'],data['Config']
        require(data['Image']==spec['image'] and data['State']['Running']
                and data['State'].get('Health',{}).get('Status')=='healthy','Pinned egress is unavailable')
        require(c.get('Entrypoint')==['python','-I','-B','/app/admin_egress.py'] and c.get('Cmd')==spec['fixed_command']
                and c.get('Healthcheck')==spec['healthcheck'],'Egress program or health policy mismatch')
        require(c.get('User')=='1000:1000' and h.get('ReadonlyRootfs') and not h.get('Privileged')
                and set(h.get('CapDrop') or [])=={'ALL'} and not h.get('CapAdd')
                and 'no-new-privileges:true' in (h.get('SecurityOpt') or []),'Unsafe egress privileges')
        require(not data.get('Mounts') and not h.get('PortBindings') and not h.get('Tmpfs')
                and not h.get('Devices') and not h.get('DeviceRequests') and h.get('PidMode','')!='host'
                and h.get('IpcMode','')!='host' and h.get('NetworkMode')!='host','Egress exposes host resources')
        networks=data.get('NetworkSettings',{}).get('Networks',{})
        require(set(networks)=={self.engine.network,spec['egress_network']}
                and networks[self.engine.network]['IPAddress']==spec['bind_ip']
                and spec['alias'] in (networks[self.engine.network].get('Aliases') or []),'Egress network/bind identity mismatch')
        for name,internal in ((self.engine.network,True),(spec['egress_network'],False)):
            network=json.loads(self.docker('network','inspect',name))[0]
            require(network.get('Driver')=='bridge' and network.get('Internal') is internal,'Egress bridge isolation mismatch')

    def check_egress(self,timeout=3):
        with self.bounded(time.monotonic()+timeout):self.validate_egress()

    def flags(self,enabled):
        return ['--admin-db=/admin/admin.sqlite3','--admin-environment='+self.config['environment'],
                '--admin-logs=/app/server/logs','--admin-port=9445',
                *(['--admin-bind=0.0.0.0'] if self.engine.c.get('admin_public_port') else [])] if enabled else []

    def mounts(self,enabled):
        return [('volume',self.config['state_volume'],'/admin',False),
                ('volume',self.config['log_volume'],'/app/server/logs',False)] if enabled else []

    def validate_world(self,cid,config):
        expected=[flag for flag in self.flags(self.enabled(cid)) if not flag.startswith('--admin-bind=')]
        actual=[s for s in config.get('Cmd',[]) if s.startswith('--admin-') and not s.startswith('--admin-bind=')]
        require(sorted(actual)==sorted(expected),'Admin world flags mismatch')

    def preflight(self):
        if self.config is None:return
        c=self.config
        for path,sha in self.pins.items():
            require(not Path(path).is_symlink() and checksum(path)==sha,'Admin runtime input changed; reload reviewed configuration')
        require(not Path(c['relay_secret_file']).stat().st_mode&0o077,'Private relay secret permissions changed')
        for key in ('state_volume','log_volume'):self.docker('volume','inspect',c[key])
        require(json.loads(self.docker('image','inspect',c['relay_image']))[0]['Id']==c['relay_image'],'Pinned relay image unavailable')
        self.validate_egress()

    def command(self):
        c=self.config
        result=['/app/deploy/admin/outbound443_admin_agent.py','--enable','--edge-origin='+c['edge_origin'],
                '--relay-secret-file=/admin-config/relay-secret','--routes-file=/admin-config/routes.json',
                '--origin-host=127.0.0.1','--origin-port=9445','--origin-server-name=localhost','--origin-ca=/certs/ca.crt']
        if c.get('upstream_proxy'):result+=['--upstream-proxy='+c['upstream_proxy']]
        return result

    def relay_mounts(self):
        return [(self.config['relay_secret_file'],'/admin-config/relay-secret'),
                (self.config['routes_file'],'/admin-config/routes.json'),
                (str(self.engine.c['certificates']/'ca.crt'),'/certs/ca.crt')]

    def existing(self):
        # A failed inspect cannot authorize stopping any other container.
        try:return json.loads(self.docker('inspect',self.name))[0]
        except Exception:return None

    def validate_relay(self,data,cid,*,running=True):
        h,c=data['HostConfig'],data['Config']
        require(data['Image']==self.config['relay_image'] and (not running or data['State']['Running']),'Admin relay image/state mismatch')
        require(c.get('Entrypoint')==['python'] and c.get('Cmd')==self.command(),'Untrusted admin relay command')
        require(h.get('NetworkMode')=='container:'+cid and not h.get('PortBindings'),'Admin relay namespace/port mismatch')
        require(h.get('ReadonlyRootfs') and not h.get('Privileged') and c.get('User')=='1000:1000'
                and set(h.get('CapDrop') or [])=={'ALL'} and not h.get('CapAdd')
                and 'no-new-privileges:true' in (h.get('SecurityOpt') or []),'Unsafe admin relay privileges')
        require(not h.get('Devices') and not h.get('DeviceRequests') and h.get('PidMode','')!='host'
                and h.get('IpcMode','')!='host' and h.get('RestartPolicy',{}).get('Name') in ('no','')
                and set(h.get('Tmpfs') or {})=={'/tmp'},'Unsafe admin relay host resources')
        labels=c.get('Labels') or {}
        require(labels.get('private.trusted-project')==self.engine.c['project'] and labels.get('private.runtime-role')=='admin-relay','Unmanaged admin relay')
        expected={(source,target) for source,target in self.relay_mounts()};distro=labels.get('desktop.docker.io/wsl-distro','');translations={}
        if re.fullmatch(r'[A-Za-z0-9_.-]+',distro):
            translations={'/run/desktop/mnt/host/wsl/docker-desktop-bind-mounts/'+distro+'/'+hashlib.sha256(source.encode()).hexdigest():source for source,target in expected}
        mounts=[m for m in data.get('Mounts',[]) if m['Type']!='tmpfs']
        actual={(translations.get(m.get('Source'),m.get('Source')),m['Destination']) for m in mounts}
        require(actual==expected and all(m['Type']=='bind' and not m['RW'] for m in mounts),'Unexpected admin relay mounts')
        return data['Id']

    def detach(self,cid,deadline=None):
        with self.bounded(deadline):return self._detach(cid)

    def _detach(self,cid):
        if self.config is None:return
        found=self.existing()
        if found:
            self.validate_relay(found,cid,running=False)
            self.docker('rm','--force',found['Id'],timeout=5)

    def attach(self,cid,deadline=None,*,restarted=False):
        with self.bounded(deadline):return self._attach(cid,restarted)

    def _attach(self,cid,restarted):
        if self.config is None:return None
        found=self.existing()
        if found:
            mode=found['HostConfig'].get('NetworkMode','')
            require(mode.startswith('container:'),'Admin relay target is not a world namespace')
            previous=mode.removeprefix('container:')
            self.validate_relay(found,previous,running=False)
            if previous==cid and self.enabled(cid) and not restarted:
                if not found['State']['Running']:self.docker('start',found['Id'],timeout=5)
                return self.validate_relay(self.inspect(found['Id']),cid)
            require((previous==cid and restarted) or not self.inspect(previous)['State']['Running'],'Previous admin world is still running')
            self.docker('rm','--force',found['Id'],timeout=5)
        if not self.enabled(cid):return None
        self.preflight();args=['create','--name',self.name,'--pull=never','--network','container:'+cid,
            '--label','private.trusted-project='+self.engine.c['project'],'--label','private.runtime-role=admin-relay',
            '--read-only','--user','1000:1000','--cap-drop','ALL','--security-opt','no-new-privileges:true','--restart','no',
            '--init','--pids-limit','32','--memory','128m','--cpus','0.5','--tmpfs','/tmp:rw,nosuid,nodev,size=16m,mode=1777']
        for source,target in self.relay_mounts():args+=['--mount','type=bind,src='+source+',dst='+target+',readonly']
        args+=['--entrypoint','python',self.config['relay_image'],*self.command()]
        created=None
        try:
            created=self.docker(*args,timeout=10).decode().strip();self.validate_relay(self.inspect(created),cid,running=False)
            self.docker('start',created,timeout=5);return self.validate_relay(self.inspect(created),cid)
        except Exception:
            if created:self.docker('rm','--force',created,timeout=5)
            raise

    def healthy(self,cid,timeout=3):
        with self.bounded(time.monotonic()+timeout):return self._healthy(cid,timeout)

    def _healthy(self,cid,timeout):
        if not self.enabled(cid):return
        self.validate_egress()
        found=self.existing();require(found is not None,'Admin relay missing');self.validate_relay(found,cid)
        # Verify private TLS and admission without reading a privileged API key.
        code="import ssl,http.client;c=http.client.HTTPSConnection('localhost',9445,context=ssl.create_default_context(cafile='/certs/ca.crt'),timeout=2);c.request('GET','/api/v1/whoami');r=c.getresponse();assert r.status==401;r.read(65536);c.close()"
        self.docker('exec','--user','1000:1000',found['Id'],'python','-I','-c',code,timeout=timeout)

    def record(self,cid):
        if not self.enabled(cid):return {'admin_enabled':False}
        found=self.existing();require(found is not None,'Admin relay missing when recording world')
        return {'admin_enabled':True,'admin_relay':self.validate_relay(found,cid),'admin_relay_image':self.config['relay_image']}
