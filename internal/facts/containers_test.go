package facts

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/klar-web-services/tripcoil/internal/dockerapi"
	"github.com/klar-web-services/tripcoil/internal/inventory"
)

// What the routes need to match a proxy's target to a container, and the reach to know which ports
// a Swarm service publishes on every node.
func TestContainerNamesAndSwarm(t *testing.T) {
	task := dockerapi.Detail{}
	task.Config.Labels = map[string]string{
		"com.docker.swarm.service.name": "shop_web", "com.docker.compose.service": "web",
		"traefik.enable": "True", "traefik.http.routers.web.rule": "Host(`shop.example.org`) && Header(`X-Token`, `planted-header-token`)",
		"traefik.http.services.api.loadBalancer.server.url":     "http://admin:planted-password@10.0.0.9:9000",
		"traefik.http.services.metrics.loadbalancer.server.url": "http://127.0.0.1:9100/planted-path",
		"traefik.http.middlewares.auth.basicauth.users":         "admin:$apr1$secret", "maintainer": "alice",
	}
	task.NetworkSettings.Networks = map[string]dockerapi.Endpoint{
		"shop_default": {NetworkID: "n1", IPAddress: "172.20.0.5", Aliases: []string{"web", "shop"}, DNSNames: []string{"web", "0123456789ab"}},
		"lan":          {NetworkID: "n2", IPAddress: "192.168.1.50", GlobalIPv6Address: "2001:db8::50"},
	}
	inv := &inventory.Inventory{Items: []inventory.Item{
		{ID: "container:shop_web.1.abc", Kind: inventory.KindContainer, Name: "shop_web.1.abc", ContainerID: "c1"},
		{ID: "container:plain", Kind: inventory.KindContainer, Name: "plain", ContainerID: "c3"},
	}}
	docker := fakeDocker{"c1": task, "c3": {}, "manager": {}}
	conts, err := (collector{ctx: context.Background(), d: Deps{Docker: docker}, inv: inv}).containers()
	if err != nil {
		t.Fatal(err)
	}
	plain, web := conts[0], conts[1]
	if !reflect.DeepEqual(web.Names, []string{"0123456789ab", "shop", "shop_web", "shop_web.1.abc", "web"}) ||
		!reflect.DeepEqual(web.Addresses, []string{"172.20.0.5", "192.168.1.50", "2001:db8::50"}) || !web.OwnAddress {
		t.Errorf("names %v, addresses %v, own address %v", web.Names, web.Addresses, web.OwnAddress)
	}
	// The mesh port only: the one published in host mode is on the container already.
	if web.Service != "shop_web" || web.MeshUnknown || !reflect.DeepEqual(web.MeshPorts, []inventory.Port{{HostPort: 8080, ContainerPort: 80, Protocol: "tcp"}}) {
		t.Errorf("service %q, mesh ports %+v, unknown %v", web.Service, web.MeshPorts, web.MeshUnknown)
	}
	// Of the routing labels of the container and of its service only the names and the ports: a rule
	// can hold a token, a URL a password, and a middleware's users are a secret.
	want := &Routing{Enable: "true", Hostnames: []string{"shop.example.org"}, Ports: []int{80, 9100}}
	if !reflect.DeepEqual(web.Routing, want) {
		t.Errorf("routing %+v", web.Routing)
	}
	if out, _ := json.Marshal(conts); strings.Contains(string(out), "planted") || strings.Contains(string(out), "apr1") {
		t.Errorf("a secret left a label: %s", out)
	}
	if !reflect.DeepEqual(plain.Names, []string{"plain"}) || len(plain.Addresses) != 0 || plain.OwnAddress || plain.Service != "" || plain.Routing != nil {
		t.Errorf("a plain container: %+v", plain)
	}

	// On a worker the service's mesh ports cannot be listed.
	delete(docker, "manager")
	conts, err = (collector{ctx: context.Background(), d: Deps{Docker: docker}, inv: inv}).containers()
	if err != nil || !conts[1].MeshUnknown || conts[1].MeshPorts != nil || conts[0].MeshUnknown {
		t.Errorf("on a worker: %+v %v", conts, err)
	}
}

func TestRoutingLabels(t *testing.T) {
	var none *Routing
	for name, c := range map[string]struct {
		labels map[string]string
		want   *Routing
	}{
		"no Traefik label":      {map[string]string{"com.docker.compose.service": "web", "traefik.docker.network": "proxy"}, nil},
		"a middleware only":     {map[string]string{"traefik.http.middlewares.auth.basicauth.users": "admin:hash"}, nil},
		"switched off":          {map[string]string{"Traefik.Enable": "FALSE"}, &Routing{Enable: "false"}},
		"not a truth value":     {map[string]string{"traefik.enable": "yes please"}, &Routing{}},
		"a router without host": {map[string]string{"traefik.tcp.routers.db.entrypoints": "pg"}, &Routing{}},
		"a port":                {map[string]string{"traefik.http.services.app.loadBalancer.server.port": " 8080 "}, &Routing{Ports: []int{8080}}},
		"no port":               {map[string]string{"traefik.http.services.app.loadbalancer.server.port": "http"}, &Routing{}},
	} {
		if got := none.read(c.labels); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %+v, want %+v", name, got, c.want)
		}
	}
}
