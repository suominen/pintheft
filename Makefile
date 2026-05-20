SITE := site
DEST := haig:/pintheft/
SSH_IDENTITY := $(HOME)/.ssh/id-kimmo-cloud-htdocs

.PHONY: build dist

build:
	cd $(SITE) && hugo --minify --gc --cleanDestinationDir

dist: build
	rsync -avz --delete --chmod=Da+rx,Fa+r -e 'ssh -i $(SSH_IDENTITY) -o IdentitiesOnly=yes' $(SITE)/public/ $(DEST)
