# QuecPython SNMP

[中文](./README_ZH.md) | English

## Overview

The Simple Network Management Protocol (SNMP) is a communication protocol used for managing and monitoring network devices in IP networks, applicable to routers, switches, servers, and other devices. Its design is lightweight and highly scalable, supporting various operating systems and network equipment. SNMP uses community strings as a simple means of access control, allowing network administrators to collect and manage device information.

The main SNMP operations include GET, used to request device information; SET, used to modify device configurations; and TRAP, used for devices to report anomalies to the management station. As the protocol has evolved, SNMP has enhanced its security features. The latest version, SNMPv3, supports message integrity, authentication, and encryption to improve communication security.

Version support: Both `client` and `server` in the current code support three versions: `SNMPv1`, `SNMPv2c`, and `SNMPv3`.

Method support: The `client` in the current code supports methods such as get, multiget, getnext, multigetnext, bulkget, set, multiset, walk, multiwalk, bulkwalk, table, bulktable and so on; The `server` in the current code supports methods such as get, set, trap and so on.

## Usage

- [SNMP Client API Reference](./client/docs/en/SNMP_Client_API_Reference.md)
- [SNMP Client Sample Code](./client/snmp_api.py)
- [SNMP Client Documentation](./client/docs/en/SNMP_Client_Documentation.md)

- [SNMP Agent API Reference](./server/docs/en/SNMP_Agent_API_Reference.md)
- [SNMP Agent Sample Code](./server/snmp_agent.py)
- [SNMP Agent Documentation](./server/docs/en/SNMP_Agent_Documentation.md)

## Contribution

We welcome contributions to improve this project! Please follow these steps to contribute:

1. Fork this repository.
2. Create a new branch (`git checkout -b feature/your-feature`).
3. Commit your changes (`git commit -m 'Add your feature'`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a Pull Request.

## License

This project is licensed under the Apache License. For more details, please see the [LICENSE](./LICENSE) file.

## Support

If you have any questions or need support, please refer to the [QuecPython Documentation](https://python.quectel.com/doc) or open an issue in this repository.