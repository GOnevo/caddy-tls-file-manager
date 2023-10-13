# File based Certificate Manager for Caddy

The same module as the original `get_certificate http <url>` but works with a file.

> requires global **ask** configuration

## Usage

**Caddyfile:**
```
{
	on_demand_tls {
		ask http://localhost:3333
	}
}

:443 {
	tls {
		get_certificate file /path/to/file.list
	}
}
```

**file.list:**
```
domain.com /etc/certificates/domain.com.bundle
domain.name.com /etc/certificates/domain.name.com.bundle
```

> the second column is the path to the file that must contain a PEM chain including the full certificate
> (with intermediates) as well as the private key.

### License

This module is open-sourced software licensed under the [MIT license](./LICENSE.md).

[Vano Devium](https://github.com/vanodevium/)

---

Made with ❤️ in Ukraine
