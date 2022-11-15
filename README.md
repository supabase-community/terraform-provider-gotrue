# Terraform Provider for GoTrue

**WARNING: This is experimental software and is not indended for production
purposes just yet. Version 2.0.0 and above will be for wider consumption.**

[GoTrue](https://github.com/supabase/gotrue) is the software behind [Supabase
Auth](https://supabase.com/auth).

This package implements a [Terraform](https://hashicorp.com/products/terraform)
provider that lets you configure some settings in GoTrue as Infrastructure as
Code.

See the `examples` directory for a full example.

## Local Development

Run the following command to build the provider:

```shell
make build
```

Run this to install the provider on your local machine:

```shell
make install
```

Then in your Terraform project you can do:

```shell
terraform init
```

to initialize Terraform. 

You may need to do:

```shell
rm -rf .terraform.lock.hcl
```

And then finally do:

```shell
terraform apply
```

to apply the change to your configured GoTrue server.
