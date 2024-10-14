# PortScout

Fast and Reliable Port Scanning Made Simple.

### Prerequisites

- [Git](https://git-scm.com/)
- [Python3](https://www.python.org/downlods/)

#### 🛠️ Installation Steps
1. Clone this project. <br>
   `git clone https://github.com/thecyberworld/port-scanner.git`
2. Navigate to the project. <br>
   `cd port-scanner`

### Usage

|     | Syntax                                                      | Examples                                     |
|:----|:------------------------------------------------------------|:---------------------------------------------|
| 1.  | `python3 scanner.py --host <ip>`                                   | `python3 scanner.py --host 192.168.0.1`             |
| 2.  | `python3 scanner.py --host <ip> <verbose>`                         | `python3 scanner.py --host 192.168.0.1 -v`          |
| 3.  | `python3 scanner.py --host <ip> -p <port_start>-<port_end>`           | `python3 scanner.py --host 192.168.0.1 -p 150-1333`    |
| 4.  | `python3 scanner.py --host <ip> -p <port_start>-<port_end> <verbose>` | `python3 scanner.py --host 192.168.0.1 -p 150-1333 -v` |

#### Port specific:

- Syntax: `python3 scanner.py --host <ip> -p <port_start>-<port_end>`

- Example: `python3 scanner.py --host 192.168.1.1 -p 0-200`
  <!-- ![port_specific](https://user-images.githubusercontent.com/44284877/179356857-4676e09e-48ac-4cb8-96e3-2fa910a15e9a.gif) -->

#### Verbose mode:

- Syntax: `python3 scanner.py --host <ip> -p <port_start>-<port_end> <verbose> `

- Example: `python3 scanner.py --host 192.168.1.1 -p 0-200 -v`
  <!-- ![Verbose mode](https://user-images.githubusercontent.com/44284877/179357933-76ef587a-9f74-4ab7-b466-164ca4fce445.gif) -->

---

> If you are new to Git and GitHub then must check out **[First Contribution](https://github.com/thecyberworld/first-contribution)** repository **first** and contribute to it before you contributing to other open-source projects.

## 👨‍💻 Contributing

- Contributions make the open source community such an amazing place to learn, inspire, and create.
- Any contributions you make are **truly appreciated**.
- Check out our [contribution guidelines](/CONTRIBUTING.md) for more information.

## 🛡️ License

port-scanner is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Support

This project needs a ⭐️ from you. Don't forget to leave a star ⭐️

---


