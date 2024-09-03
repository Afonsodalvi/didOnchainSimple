// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

// Importações necessárias
import "@openzeppelin/contracts/access/Ownable.sol";
import "@onchain-id/solidity/contracts/Identity.sol";
import "@onchain-id/solidity/contracts/ClaimIssuer.sol";
import {IClaimIssuer} from "@onchain-id/solidity/contracts/interface/IClaimIssuer.sol";


/**
 * @title Smart Contract simplificado de did.
 * @author Afonso Dalvi (@Afonsodalvi).
 * @dev Use como forma de aprendizado.
 */
contract DidKYC is Identity, Ownable {

    IClaimIssuer public claimIssuerContract;

    uint256 public constant CLAIM_TYPE_KYC = 1;
    address immutable s_HSM; //Manager

    // Mapeia endereços autorizados
    mapping(address => bool) public isAuthorized;

    event AddressAuthorized(address indexed addr);
    event AddressUnauthorized(address indexed addr);

    error Unauthorized(address addr);

    constructor(address _hsm)
        Ownable(_hsm)
        Identity(_hsm,false) //ja gera uma identidade
    {
        s_HSM = _hsm;
        authorizeAddress(_hsm);
    }

    // Função para autorizar um endereço (só o proprietário pode chamar)
    function authorizeAddress(address addr) public onlyOwner {
        isAuthorized[addr] = true;
        emit AddressAuthorized(addr);
    }

    // Função para desautorizar um endereço (só o proprietário pode chamar)
    function unauthorizeAddress(address addr) public onlyOwner {
        isAuthorized[addr] = false;
        emit AddressUnauthorized(addr);
    }

    // Função para verificar se um endereço está autorizado e possui KYC e AML válidos
    function isKYCAMLApproved(address addr) public view returns (bool) {
        // Verifica se o endereço está autorizado
        IIdentity identityContract = IIdentity(address(this));
        IClaimIssuer claimIssuer = IClaimIssuer(addr);

        if (!isAuthorized[msg.sender] && !isAuthorized[addr]) revert Unauthorized(msg.sender);

        // Verifica se a identidade do endereço possui claims válidos de KYC e AML
        bytes32[] memory kycClaims = identityContract.getClaimIdsByTopic(CLAIM_TYPE_KYC);

        bool hasKYC = false;

        // Valida se o claim KYC foi emitido pelo ClaimIssuer confiável e não foi revogado
        for (uint256 i = 0; i < kycClaims.length; i++) {
            (,, address issuer, bytes memory signature, bytes memory data,) = identityContract.getClaim(kycClaims[i]);
            //require(issuer == addr, "Not exist issuer"); caso queira inserir uma condição para checar a existencia do emissor
            if (claimIssuer.isClaimValid(identityContract, CLAIM_TYPE_KYC, signature, data)) {
                hasKYC = true;
                break;
            }
        }

        return hasKYC;
    }
}
