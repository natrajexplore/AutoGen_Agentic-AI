# Third-party notices

ConfigGuard is licensed under the GNU General Public License v3.0 or later (see [LICENSE](LICENSE)).
It depends on the third-party open-source packages listed below, which are installed from PyPI
and are **not** vendored in this repository. Each package remains under its own license; the full
license text and copyright notices ship with each installed package (in its `*.dist-info` folder)
and are available at the project URL. If you redistribute ConfigGuard bundled with its
dependencies (for example as a container image or installer), include those license texts and,
for Apache-2.0 packages, any `NOTICE` files they provide.

## License compatibility

- **ciscoconfparse2** is licensed **GPL-3.0-only** and is imported directly by ConfigGuard. ConfigGuard is
  therefore licensed GPL-3.0-or-later, so the combined work can be distributed under GPL-3.0.
- All other runtime dependencies use permissive licenses (MIT, BSD, ISC, Apache-2.0, PSF, MIT-CMU, 0BSD)
  or the file-level copyleft MPL-2.0 (used unmodified), all compatible with GPL-3.0.

## Runtime dependencies

Generated from the installed package metadata for the pinned versions in `requirements.txt`.

| Package | Version | License | Direct dependency | Project |
|---|---|---|---|---|
| autogen-agentchat | 0.7.5 | MIT License | yes | https://pypi.org/project/autogen-agentchat/ |
| autogen-ext | 0.7.5 | MIT License | yes | https://pypi.org/project/autogen-ext/ |
| ciscoconfparse2 | 0.9.18 | GPL-3.0-only | yes | http://github.com/mpenning/ciscoconfparse2 |
| fastapi | 0.142.2 | MIT | yes | https://github.com/fastapi/fastapi |
| pydantic | 2.12.5 | MIT | yes | https://github.com/pydantic/pydantic |
| python-dotenv | 1.1.1 | BSD License | yes | https://github.com/theskumar/python-dotenv |
| python-multipart | 0.0.32 | Apache-2.0 | yes | https://github.com/Kludex/python-multipart |
| PyYAML | 6.0.3 | MIT License | yes | https://pyyaml.org/ |
| regex | 2026.9.29 | Apache-2.0 AND CNRI-Python | yes | https://github.com/mrabarnett/mrab-regex |
| uvicorn | 0.54.0 | BSD-3-Clause | yes | https://uvicorn.dev/ |
| websockets | 17.1 | BSD-3-Clause | yes | https://github.com/python-websockets/websockets |
| aiofiles | 25.1.0 | Apache Software License |  | https://github.com/Tinche/aiofiles |
| annotated-doc | 0.0.5 | MIT |  | https://github.com/fastapi/annotated-doc |
| annotated-types | 0.8.0 | MIT |  | https://github.com/annotated-types/annotated-types |
| anyio | 4.15.1 | MIT |  | https://github.com/agronholm/anyio |
| attrs | 26.1.0 | MIT |  | https://github.com/python-attrs/attrs |
| autogen-core | 0.7.5 | MIT License |  | https://pypi.org/project/autogen-core/ |
| certifi | 2026.7.22 | Mozilla Public License 2.0 (MPL 2.0) |  | https://github.com/certifi/python-certifi |
| charset-normalizer | 3.5.2 | see package |  | https://github.com/jawah/charset_normalizer/blob/master/CHANGELOG.md |
| click | 8.5.0 | BSD-3-Clause |  | https://github.com/pallets/click/ |
| colorama | 0.4.6 | BSD License |  | https://github.com/tartley/colorama |
| dnspython | 2.8.0 | ISC License (ISCL) |  | https://www.dnspython.org |
| h11 | 0.16.0 | MIT License |  | https://github.com/python-hyper/h11 |
| hier-config | 2.3.1 | MIT License |  | https://pypi.org/project/hier-config/ |
| httpcore2 | 2.13.1 | BSD-3-Clause |  | https://github.com/pydantic/httpx2 |
| httpx2 | 2.13.1 | BSD-3-Clause |  | https://github.com/pydantic/httpx2 |
| httpx2-jsfetch | 1.0 | BSD-3-Clause |  | https://pypi.org/project/httpx2-jsfetch/ (installed only on Emscripten / WebAssembly) |
| hypothesis | 6.152.7 | MPL-2.0 |  | https://hypothesis.works |
| idna | 3.20 | BSD-3-Clause |  | https://github.com/kjd/idna |
| jiter | 0.17.0 | MIT |  | https://github.com/pydantic/jiter/ |
| jsonref | 1.1.0 | see package |  | https://github.com/gazpachoking/jsonref |
| libpass | 1.9.3 | BSD License |  | https://github.com/notypecheck/passlib |
| loguru | 0.7.3 | MIT License |  | https://github.com/Delgan/loguru |
| macaddress | 2.0.2 | see package |  | https://github.com/mentalisttraceur/python-macaddress |
| markdown-it-py | 4.2.0 | MIT License |  | https://github.com/executablebooks/markdown-it-py |
| mdurl | 0.1.2 | MIT License |  | https://github.com/executablebooks/mdurl |
| openai | 3.24.0 | Apache-2.0 |  | https://github.com/openai/openai-python |
| opentelemetry-api | 1.45.0 | Apache-2.0 |  | https://github.com/open-telemetry/opentelemetry-python/tree/main/opentelemetry-api |
| pillow | 12.3.0 | MIT-CMU |  | https://python-pillow.github.io |
| protobuf | 5.29.6 | see package |  | https://developers.google.com/protocol-buffers/ |
| pydantic_core | 2.41.5 | MIT |  | https://github.com/pydantic/pydantic-core |
| Pygments | 2.21.0 | BSD-2-Clause |  | https://pygments.org |
| pyparsing | 3.3.2 | MIT |  | https://github.com/pyparsing/pyparsing/ |
| requests | 2.34.2 | Apache Software License |  | https://github.com/psf/requests |
| rich | 15.0.0 | MIT License |  | https://github.com/Textualize/rich |
| sniffio | 1.3.1 | MIT License; Apache Software License |  | https://github.com/python-trio/sniffio |
| sortedcontainers | 2.4.0 | Apache Software License |  | http://www.grantjenks.com/docs/sortedcontainers/ |
| starlette | 1.7.0 | BSD-3-Clause |  | https://github.com/Kludex/starlette |
| tiktoken | 0.14.0 | see package |  | https://github.com/openai/tiktoken |
| toml | 0.10.2 | MIT License |  | https://github.com/uiri/toml |
| traitlets | 5.15.0 | BSD License |  | https://github.com/ipython/traitlets |
| truststore | 0.10.4 | MIT |  | https://github.com/sethmlarson/truststore |
| typeguard | 4.5.2 | MIT |  | https://github.com/agronholm/typeguard |
| types-PyYAML | 6.0.12.20260906 | Apache-2.0 |  | https://github.com/python/typeshed |
| typing-inspection | 0.4.4 | MIT |  | https://github.com/pydantic/typing-inspection |
| typing_extensions | 4.16.0 | PSF-2.0 |  | https://github.com/python/typing_extensions |
| urllib3 | 2.8.0 | MIT |  | https://github.com/urllib3/urllib3/blob/main/CHANGES.rst |
| win32_setctime | 1.2.0 | MIT License |  | https://github.com/Delgan/win32-setctime |

## Other referenced material

| Item | Use in ConfigGuard | License / terms |
|---|---|---|
| Microsoft AutoGen source (`reference/autogen`) | Optional read-only clone for checking APIs; gitignored, not distributed | MIT |
| Cisco *Guide to Harden Cisco IOS Devices* | Linked as a reference in reports; no text reproduced | © Cisco Systems, Inc. |
| NIST SP 800-53 Rev. 5 | Control identifiers only | U.S. Government work |
| PCI DSS v4.0 | Requirement identifiers only; no standard text reproduced | © PCI Security Standards Council |
| ISO/IEC 27001:2022 | Annex A control identifiers only; no standard text reproduced | © ISO/IEC |
| CIS Cisco IOS Benchmark | Inspiration only; baseline rules use ConfigGuard's own IDs and wording | © Center for Internet Security |

## Development-only dependencies

pytest (MIT), httpx (BSD-3-Clause) and ruff (MIT, run via `uvx`) are used only for testing and linting and are not
required at runtime.
