module github.com/gmcorenet/sdk-gmcore-transport

go 1.23

require (
	github.com/gmcorenet/sdk-gmcore-config v1.0.0
	gorm.io/gorm v1.25.10
)

require (
	github.com/gmcorenet/sdk-gmcore-error v1.0.0 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/kr/text v0.2.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace (
	github.com/gmcorenet/sdk-gmcore-config => ../gmcore-config
	github.com/gmcorenet/sdk-gmcore-error => ../gmcore-error
)
