# Resources

This document lists resources and documentation that can help you understand the Modbus protocol, work with the `pymodbus` library for complex tasks that demand coding solutions, bypass the limitations of commonly used command line tools, and get acquainted with the structured text for the brewery's PLC control logic hosted in this repository.

## Modbus Protocol

Modbus is a communication protocol developed for industrial applications to facilitate communication among various electronic devices. Understanding Modbus is crucial for working with PLCs in industrial settings, including breweries.

- [Modbus.org](http://www.modbus.org/) - The official Modbus website provides comprehensive documentation, standards, and resources for the Modbus protocol.
- [Modbus Technical Resources](http://www.modbus.org/tech.php) - Access technical specifications, implementation guides, and more to deepen your understanding of Modbus.

## pymodbus Library

The `pymodbus` library is a full-featured Python implementation of the Modbus protocol. It allows for easy communication with Modbus devices from Python applications.

- [pymodbus Documentation](https://pymodbus.readthedocs.io/en/latest/) - Official documentation for the `pymodbus` library, including installation instructions, tutorials, and API references.
- [pymodbus GitHub Repository](https://github.com/riptideio/pymodbus) - The source code and additional resources for the `pymodbus` library.

## Brewery PLC Control Logic

In our brewery's control system, we utilize various programming languages, including Ladder Logic, Function Block Diagram (FBD), and Sequential Function Chart (SFC), to design and implement the automation logic that governs our brewing process. Each of these languages offers unique advantages for visualizing and developing complex control sequences, allowing our engineers to select the most appropriate tool for each task.

Despite the diversity of programming languages available, all logic is ultimately compiled down to Structured Text (ST) before being loaded into the PLCs. Structured Text provides a high level of flexibility and precision, making it an ideal format for executing the compiled logic across different types of PLC hardware. This approach ensures that our brewing process is automated and optimized efficiently, regardless of the initial programming language used for development.

- [Structured Text Programming Guide](https://www.plcacademy.com/structured-text-tutorial/) - A tutorial on structured text programming, an IEC 61131-3 standard, which is used for creating PLC programs.

For any questions or contributions to the PLC control logic, please contact the repository maintainers.

---

We hope these resources help you navigate and contribute to our project effectively. Happy brewing!
