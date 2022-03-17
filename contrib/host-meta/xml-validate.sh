#!/bin/sh
exec xmllint --noout --schema xrd-1.0-os.xsd "$1"
