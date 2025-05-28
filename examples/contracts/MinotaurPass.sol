// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "./MinutaurUri.sol";

contract MinotaurPass is  MinutaurUri, Ownable {
    constructor() {
        tokenId = 1;
    }

    mapping(address => bool) authorized;
    mapping (address => uint256) ownerTokenId;
    uint256 tokenId;

    function setAuthorized(address addr, bool val) public onlyOwner{
        authorized[addr] = val;
    }

    function setValues(string memory _name_, string memory _description, string memory _imageUrl) public onlyOwner{
        _setValues(_name_, _description, _imageUrl);
    }

    function safeMint(address to) public {
        require(ownerTokenId[to] == 0, "Already Minted");

        ownerTokenId[to] = tokenId;

        _setTokenLastWing(tokenId, "00.00.00");

        tokenId++;

        _safeMint(to, tokenId -1);
    }

    function updateUri(address addr, string memory date) public {
        require(authorized[msg.sender], "caller not authorized");

        _setTokenLastWing(ownerTokenId[addr], date);

    }

    function checkOwnerTokenId(address addr) public view returns (uint256 id){
        return ownerTokenId[addr];
    }

    // The following functions are overrides required by Solidity.

    // Block token transfers
    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 _tokenId, /* firstTokenId */
        uint256 batchSize
    ) internal virtual override{
    require(from == address(0), "Err: token transfer is BLOCKED");   
    super._beforeTokenTransfer(from, to, _tokenId, batchSize);  
    }

   
}