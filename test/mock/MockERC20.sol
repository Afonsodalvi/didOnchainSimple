// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Importações necessárias
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockERC20 is ERC20 {
    constructor() ERC20("Mytoken", "mytoken") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
