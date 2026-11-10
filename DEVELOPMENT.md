# AntiSSRF Development

## Library Development

- [AntiSSRF .NET Library](dotnet/DEVELOPMENT.md)
- [AntiSSRF Node.js Library](nodejs/DEVELOPMENT.md)
- [AntiSSRF Python Library](python/DEVELOPMENT.md)

## Documentation Development

### Prerequisites

- Jekyll (for GitHub Pages)
- Ruby 3.4 or later
- Bundler (`gem install bundler`)

### Useful Commands

Run these commands from the `docs` directory.

#### Install and Build

- Install dependencies: `bundle install`
- Build the site: `bundle exec jekyll build --destination _site/AntiSSRF`

#### Preview Locally

- Preview locally: `bundle exec jekyll serve`

Open the preview at <http://localhost:4000/AntiSSRF/>. Restart the preview server after changing [`_config.yml`](docs/_config.yml).

#### Validate Links

- Validate internal links after building the site: `bundle exec htmlproofer ./_site --disable-external`
