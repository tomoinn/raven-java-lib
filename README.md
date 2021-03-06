This is a Java API to use when creating a client which wishes to authenticate against the University of Cambridge's single-sign-on servive 'Raven'. It implements the client parts of the protocol described [here](https://raven.cam.ac.uk/project/waa2wls-protocol.txt), currently using version 1 of the specification.

Javadocs are available [here](http://tomoinn.github.io/raven-java-lib/apidocs/index.html), the maven site containig reports etc can be found [here](http://tomoinn.github.io/raven-java-lib).

This library has not been uploaded to any repositories (yet), to install it you will need to do the following:

```bash
git clone https://github.com/tomoinn/raven-java-lib.git
cd raven-java-lib
mvn install
```

To add as a dependency to your maven project use:

```xml
<dependency>
  <groupId>gs.spri</groupId>
  <artifactId>rslib</artifactId>
  <version>2.0-SNAPSHOT</version>
</dependency>
```
This library is released under the GPL v2 and includes contributions from Matthew Lavy, Alistair Turnbull and Tom Oinn. It is inspired by code from the [Java Raven Toolkit](http://raven.cam.ac.uk/project/java-toolkit/).