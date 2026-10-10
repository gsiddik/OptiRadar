OptiRadar is the connected vehicle tracking server of the Opti product family,
based on the open source Traccar server (Apache License 2.0).

Linux   - run optiradar.run as root; it installs to /opt/optiradar and enables the
          optiradar service (an older /opt/traccar installation is moved over).
Windows - run optiradar-setup.exe; it installs the OptiRadar service.
Other   - unzip optiradar-other-<version>.zip and start
          java -jar tracker-server.jar conf/optiradar.xml

Configuration: conf/optiradar.xml. Single sign-on and events with OptiNexus:
see docs/optinexus-sso.md in the OptiRadar repository.
