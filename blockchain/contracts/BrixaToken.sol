// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract BrixaToken is ERC20, Ownable {
    uint8 private constant DECIMALS = 18;
    uint256 private constant TOTAL_SUPPLY = 10_000_000 * 10**DECIMALS; // 10 million tokens

    constructor() ERC20("Brixa Token", "BRIXA") Ownable(msg.sender) {
        _mint(msg.sender, TOTAL_SUPPLY);
    }

    function decimals() public pure override returns (uint8) {
        return DECIMALS;
    }

    function burn(uint256 amount) public {
        _burn(msg.sender, amount);
    }

    function burnFrom(address account, uint256 amount) public {
        _spendAllowance(account, msg.sender, amount);
        _burn(account, amount);
    }
}
