source "https://rubygems.org"

# Tema Chirpy - blog técnico optimizado para ciberseguridad
gem "jekyll-theme-chirpy", "~> 7.1"

group :test do
  gem "html-proofer", "~> 5.0"
end

# Soporte para Windows / JRuby
platforms :mingw, :x64_mingw, :mswin, :jruby do
  gem "tzinfo", ">= 1", "< 3"
  gem "tzinfo-data"
end

gem "wdm", "~> 0.2.0", :platforms => [:mingw, :x64_mingw, :mswin]
gem "http_parser.rb", "~> 0.6.0", :platforms => [:jruby]
