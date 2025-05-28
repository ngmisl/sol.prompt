// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "./MinotaurPass.sol";

contract MinotaurToken is ERC20, Pausable, Ownable {
    constructor(MinotaurPass _minotaurPass) ERC20("Minotaur", "MNT") {
        minotaurPass = _minotaurPass;
    }

    address[] players;

    uint lastRoundTime;

    uint256 incrementalTime;

    MinotaurPass immutable minotaurPass;

    function pause() public onlyOwner {
        _pause();
    }

    function unpause() public onlyOwner {
        _unpause();
    }

    //Add Voucher system in the future
    function mint(address to, uint256 amount, string memory date) public {
        require(block.timestamp + incrementalTime >= lastRoundTime);

        lastRoundTime = block.timestamp;
        minotaurPass.updateUri(to, date);
        delete players;
        _mint(to, amount);
        
    }

    function checkLastRoundTime() view public returns (bool) {
        require(block.timestamp + incrementalTime >= lastRoundTime);

        return true;
    }

    function startNewRound() public {
        require(block.timestamp + incrementalTime >= lastRoundTime);
        players.push(msg.sender);
    }

    function setIncreamental(uint256 time) public onlyOwner {
        incrementalTime = time;
    }

    function getPlayers() view public returns (address[] memory _players){
        return players;
    }

    function _beforeTokenTransfer(address from, address to, uint256 amount)
        internal
        whenNotPaused
        override
    {
        super._beforeTokenTransfer(from, to, amount);
    }
}