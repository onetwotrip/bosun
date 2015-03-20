package conf

import (
	"regexp"
	"strings"
	"testing"
)

var dependencyTestConfig = `
	tsdbHost=localhost:4242
	macro host_based{
		depends = alert("scollector.down","warn")
	}
	alert ping.host{
		$q = max(rename(q("sum:bosun.ping.timeout{dst_host=*,host=*}", "1m", ""), "host=source,dst_host=host"))
		warn = $q
	}
	alert scollector.down{
		depends = alert("ping.host", "warn")
		$a = avg(q("avg:os.cpu{host=*}", "1m", "")) < -100
		warn = $a
	}
	alert os.cpu{
		macro = host_based
		warn = avg(q("avg:os.cpu{host=*}", "1m", "")) > 50
	}
`

func TestConfDependencies(t *testing.T) {
	c, err := New("test.conf", dependencyTestConfig)
	if err != nil {
		t.Fatal(err)
	}
	templates, err := c.AlertTemplateStrings()
	if err != nil {
		t.Fatal(err)
	}
	expected := "ping.host,scollector.down,host_based,os.cpu"
	assertTemplateSequenceEqual(t, templates, "os.cpu", expected)

	expected = "ping.host"
	assertTemplateSequenceEqual(t, templates, "ping.host", expected)
}

func assertTemplateSequenceEqual(t *testing.T, templates *AlertTemplateStrings, alert, expected string) {
	result := templateToSequence(templates.Alerts[alert])
	if result != expected {
		t.Fatalf("Bad template sequence. Expected: %s. Got: %s.", expected, result)
	}
}

// Returns general order of components in template string. Comma delimited list of names, from top to bottom.
func templateToSequence(template string) string {
	regex := regexp.MustCompile(`(alert|macro|notification|lookup) ([a-z0-9\._]+)(\s*)?\{`)
	matches := regex.FindAllStringSubmatch(template, -1)
	names := []string{}
	for _, match := range matches {
		names = append(names, match[2])
	}
	return strings.Join(names, ",")
}

var kyleConfig = `tsdbHost=localhost:4242
smtpHost=ny-mail02:25
emailFrom=bosun-test@stackexchange.com
stateFile = ../bosun.state
checkFrequency = 30s
responseLimit = 5242880
unknownThreshold = 2
ping = true

notification default {
    email = kyle@stackoverflow.com
    print = true
}

template unknown {
    subject = {{.Name}}: {{.Group | len}} unknown alerts
    body = ` + "`" + `
    <p>Time: {{.Time}}
    <p>Name: {{.Name}}
    <p>Alerts:
    {{range .Group}}
        <br>{{.}}
    {{end}}` + "`" + `
}

unknownTemplate = unknown

template generic {
    body = ` + "`" + `<a href="{{.Ack}}">Acknowledge alert</a>
    <p>Alert definition:
    <p>Name: {{.Alert.Name}}
    <p>Crit: {{.Alert.Crit}}

    <p>Tags

    <table>
        {{range $k, $v := .Group}}
            {{if eq $k "host"}}
                <tr><td>{{$k}}</td><td><a href="{{$.HostView $v}}">{{$v}}</a></td></tr>
            {{else}}
                <tr><td>{{$k}}</td><td>{{$v}}</td></tr>
            {{end}}
        {{end}}
    </table>

    <p>Computation

    <table>
        {{range .Computations}}
            <tr><td>{{.Text}}</td><td>{{.Value}}</td></tr>
        {{end}}
    </table>` + "`" + `
    subject = {{.Last.Status}}: {{.Alert.Name}}:  on {{.Group.host}}
}

macro host_based {
    depends = alert("scollector.down", "warn")
    #depends = alert("ping.host", "warn")
}

alert ping.host {
    template = generic
    # also dns resolution
    #$q = max(q("sum:bosun.ping.timeout{dst_host=*,host=ny-kbrandt02}", "1m", ""))
    $q = max(rename(q("sum:bosun.ping.timeout{dst_host=*,host=*}", "1m", ""), "host=source,dst_host=host"))
    warn = $q
    warnNotification = default
}

alert scollector.down {
	template = generic
	# Generic stuff to suggest unknown. Basically a bunch of possible conditions
	# that should never become true. Won't work with Cisco / VMWare. They will need
	# different metrics.
	depends = alert("ping.host", "warn")
	$a = avg(q("avg:os.cpu{host=*}", "1m", "")) < -100
	$b = avg(q("avg:os.mem.percent_free{host=*}", "1m", "")) < -100
	$c = avg(q("avg:os.net.bytes{host=*}", "1m", "")) < -100
	warn = $a || $b || $c
	warnNotification = default

}

alert os.cpu {
    macro = host_based
    template = generic
    $q = avg(q("avg:rate{counter,,1}:os.cpu{host=*}", "1m", ""))
    warn = $q < 99
    warnNotification = default
}


alert os.cpu.no_depedency {
    template = generic
    $q = avg(q("avg:rate{counter,,1}:os.cpu{host=*}", "1m", ""))
    warn = $q < 99
    warnNotification = default
}

alert always.good {
    macro = host_based
    template = generic
    $q = avg(q("avg:rate{counter,,1}:os.cpu{host=*}", "1m", ""))
    warn = $q > 200
    warnNotification = default
}

alert os.mem {
    macro = host_based
    template = generic
    $q = avg(q("avg:os.mem.percent_free{host=*}", "1m", ""))
    crit = $q < 99
    critNotification = default
}
`

func TestKyleDependencies(t *testing.T) {
	c, err := New("test.conf", kyleConfig)
	if err != nil {
		t.Fatal(err)
	}
	templates, err := c.AlertTemplateStrings()
	if err != nil {
		t.Fatal(err)
	}
	expected := "default,ping.host,scollector.down,host_based,always.good"
	assertTemplateSequenceEqual(t, templates, "always.good", expected)

}
