// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/utils/Base64.sol";

abstract contract MinutaurUri is ERC721 {

    mapping (uint256 => string) lastWin;

    string _name;
    string description;
    string imagenUrl;

    constructor()ERC721("MinotaurPass", "MNP"){
    }

    function _setValues(string memory _name_, string memory _description, string memory _imageUrl) internal {
        _name = _name_;
        description = _description;
        imagenUrl = _imageUrl;
    }

    function tokenURI(uint256 tokenId) public view virtual override returns (string memory) {
        _requireMinted(tokenId);

        string memory json = Base64.encode(
            bytes(
                string(
                    abi.encodePacked(
                    '{"name": "', _name,
                    '","description":"', description, 
                    '", "image": "', imagenUrl,
                    '", "tokenId": "', Strings.toString(tokenId),
                    '","attributes": [ { "trait_type": "last_win", "value": "',
                    lastWin[tokenId],               
                    '"} ]}'
                )

                )
            )
        );

        string memory output = string(
            abi.encodePacked("data:application/json;base64,", json)
        );

        return output;
    }

    function _setTokenLastWing(uint256 tokenId, string memory data) internal virtual {
        lastWin[tokenId] = data;
    }
 
}