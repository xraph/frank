// Copyright 2022-present Wakflo
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

lint {
    naming {
        match   = "^[a-z_]+$"
        message = "must be lowercase"
    }
}

data "composite_schema" "project" {
    # schema "public" {
    #     url = "file://scripts/types.sql"
    # }

    schema "public" {
        url = "ent://ent/schema"
    }
}

env "local" {
    src = data.composite_schema.project.url

    migration {
        dir = "file://migrations"
        format = golang-migrate
#         baseline = <<SQL
#            CREATE COLLATION en_natural (LOCALE = 'en-US-u-kn-true',PROVIDER = 'icu');
#         SQL
    }

    format {
        migrate {
            diff = "{{ sql . \"  \" }}"
        }
    }
}
