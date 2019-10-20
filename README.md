# mixing-security-realm-plugin
Plugin for jenkins to mix local Hudson users with other security realm, such as LDAP

## Usage

  Install this plugin, and then go to `Manage Jenkins` -> `Security Configure`. A `Mixing` realm will appear in the
  `Access Control` section. Check it will enable you to use multiple security realms at the same time.
  ![Chose mixing security realm](docs/mixing-security-realm.jpg)
  Mixing security is based on jenkins own user database. You can choose one or more installed security realm, which are
  configured as if they were used alone, and they can be moved to determine their order.
  The option `Current Realm Priority` means that the base realm is used as a priority or backup.



## Build and Run

  Just run the flow command to start a jenkins instance with this plugin.
```bash
$ mvn hpi:run -Djetty.port=8090
```

  Build and package this plugin, and then install it to Jenkins
```bash
$ mvn clean package
```

## LOG

  You can add new log recorder in `Manage Jenkins` -> `System Log`, logger is `hudson.security.MixingSecurityRealm`, and
  log level must be `fine`.
  ![mixing-security-log.jpg](docs/mixing-security-log.jpg)
