## Docs

### Requirements

- [redocly](https://redocly.com/docs/cli/)
- [spectral](https://meta.stoplight.io/docs/spectral/)

### Bundle & lint the API spec

From **signare/app** repository, run:
```bash
make tools.generate
```

### Build and serve documentation locally

From **signare/app** repository, run:
```bash
make tools.start_docs
```
You can also run the following command to stop and delete the created container:
```bash
make tools.stop_docs
```

> Note: the Changelog page is generated from the canonical root `CHANGELOG.md` by
> `make tools.sync_changelog` (a prerequisite of `tools.start_docs`). Any other docs
> build path must run it first, or the Changelog page is dropped from the site.
