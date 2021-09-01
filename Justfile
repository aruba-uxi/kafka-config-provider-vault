# Show this message and exit.
help:
  @just --list --unsorted

clean:
	rm -rf target

# Run all lints.
build:
  @just clean
  mvn clean package
