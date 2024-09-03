// SPDX-License-Identifier: MIT
/*solhint-disable compiler-version */
pragma solidity ^0.8.20;

/// -----------------------------------------------------------------------
/// Imports
/// -----------------------------------------------------------------------

import {Test, console} from "forge-std/Test.sol";
import {Identity, IIdentity} from "@onchain-id/solidity/contracts/Identity.sol";
import {ClaimIssuer} from "@onchain-id/solidity/contracts/ClaimIssuer.sol";
import {DidKYC} from "../src/DidKYC.sol";
import {MockERC20} from "./mock/MockERC20.sol";
import {HelperConfig} from "../../../script/HelperConfig.s.sol";

contract DidKYCTest is Test {

    ClaimIssuer public claimIssuer;
    ClaimIssuer public claimIssuer2;
    ClaimIssuer public claimIssuerNotApproved;
    DidKYC public didKYC;

    MockERC20 public token;

    uint256 public constant KYC_CLAIM_TOPIC = 1;
    uint256 public constant AML_CLAIM_TOPIC = 2;

    //gerando enderecos para interagir
    address public wallet1 = makeAddr("wallet1");
    address public wallet2 = makeAddr("wallet2");

    address public hsm = makeAddr("hsm"); //cliente Management DidKYC

    address public hsmIssuer = makeAddr("hsmIssuer"); //cliente Management ClaimIssuer

    address public invalidAddr = makeAddr("invalidAddr");

    function setUp() public {
        
        //Managemet do contrato de claimIssuer identidades deve ser o mesmo
        vm.startBroadcast(hsm);
        claimIssuer = new ClaimIssuer(hsm);

        //Ao inserir um diferente ele deve ter a permissao na identidade com chave de claim
        claimIssuer2 = new ClaimIssuer(hsmIssuer);

        //endereco nao autorizado
        claimIssuerNotApproved = new ClaimIssuer(invalidAddr);

        //Managemet da did
        didKYC = new DidKYC(hsm);

        //para realizar um execute na identidade
        token = new MockERC20();

        // Autoriza para interagir com o contrato de did
        didKYC.authorizeAddress(address(claimIssuer)); // O proprio Issuer valida
        didKYC.authorizeAddress(wallet1); //pode ser um cliente externo que queira validar o KYC
        
        vm.stopBroadcast();
    }

    function testAddClaimDidKYC() public {
        //Assinatura dos dois issuer existentes - com hsms diferentes
        (bytes memory signature, bytes memory dataKYC) = setSig(hsm,"hsm","KYC Information");
        (bytes memory signatureHsmIssuer, bytes memory dataKYC2) = setSig(hsmIssuer,"hsmIssuer","KYC info2");
    
        //  1 = MANAGEMENT, 2 = ACTION, 3 = CLAIM
        //adicionando a chave de permissao de Claim para o hsmIssuer
        vm.prank(hsm);
        didKYC.addKey(keccak256(abi.encode(address(hsmIssuer))), 3, 1);

        // Adiciona o claim e no processo verifica se a assinatura é valida
        vm.prank(hsm); //a mesma hsm é manager do claimIssuer e da identidade e não precisa dar permissão de Claim
        bytes32 claimID_1 = didKYC.addClaim(KYC_CLAIM_TOPIC, 1, address(claimIssuer), signature, dataKYC, "https://example.com/kyc-proof");

        // Adiciona o claim e verifica pelo segundo emissor se esta aprovado
        vm.prank(hsmIssuer);//hsm diferente e adicionamos anteriormente a key de Claim
        bytes32 claimID_2 = didKYC.addClaim(KYC_CLAIM_TOPIC, 1, address(claimIssuer2), signatureHsmIssuer, dataKYC2, "https://example.com/kyc-proof");

        vm.prank(hsm);
        bool claimverify = claimIssuer.isClaimValid(IIdentity(didKYC), KYC_CLAIM_TOPIC, signature, dataKYC);
        
        vm.prank(hsm);
        bool claimverify2 = claimIssuer2.isClaimValid(IIdentity(didKYC), KYC_CLAIM_TOPIC, signatureHsmIssuer, dataKYC2);
        //check
        (,,address issuer1,bytes memory sig1,,) = didKYC.getClaim(claimID_1);
        (,,address issuer2,bytes memory sig2,,) = didKYC.getClaim(claimID_2);
        
        // Verifica se a identidade tem KYC aprovada pelo claimIssuer
        vm.prank(wallet1); // a empresa da wallet1 quer verificar se a identidade tem KYC aprovado pelo ClaimIssuer2
        bool isApproved = didKYC.isKYCAMLApproved(address(claimIssuer2));
        console.log("Aprovado?", isApproved);

        vm.prank(wallet1); // a empresa da wallet1 quer verificar se a identidade tem KYC aprovado pelo claimIssuerNotApproved
        bool isNotApproved = didKYC.isKYCAMLApproved(address(claimIssuerNotApproved));
        console.log("Aprovado?", isNotApproved);

        //check claims
        assertEq(claimverify, true);
        assertEq(claimverify2, true);

        //check signatures e issuers
        assertEq(issuer1, address(claimIssuer));
        assertEq(sig1, signature);
        assertEq(issuer2, address(claimIssuer2));
        assertEq(sig2, signatureHsmIssuer);

        //check de aprovação
        assertEq(isApproved, true);
        assertEq(isNotApproved, false);
    }

    function testExecute() external {
        //hsm is a manager
        (bytes memory signature, ) = setSig(hsm,"hsm","KYC Information");

        //  1 = MANAGEMENT, 2 = ACTION, 3 = CLAIM, 4 = ENCRYPTION
        // vm.prank(address(didKYC));
        // didKYC.addKey(keccak256(abi.encode(wallet1)), 3, 1);

        vm.prank(hsm);
        didKYC.addKey(keccak256(abi.encode(wallet2)), 2, 1);

        //execute works fine:
        bytes memory _data = "data qualquer";
        vm.deal(address(didKYC), 10 ether);

        vm.prank(wallet2);
        didKYC.execute(wallet1, 1 ether, _data);

        uint256 balanceWallet = wallet1.balance;
        assertEq(balanceWallet, 1 ether);
        console.log(balanceWallet);

        uint256 balanceContract = address(didKYC).balance;
        assertEq(balanceContract, 9 ether);
        console.log(balanceContract);

        //testando com interacao sem nenhuma permissao
        vm.prank(invalidAddr); //endereco sem nenhuma key adicionada
        didKYC.execute(invalidAddr, 1 ether, _data);

        uint256 balanceinvalid = invalidAddr.balance;
        assertEq(balanceinvalid, 0);
        console.log(balanceinvalid);

        uint256 balanceContract2 = address(didKYC).balance;
        assertEq(balanceContract2, 9 ether);
        console.log(balanceContract2);

        //teste de adicionar key 
        vm.prank(hsm);
        didKYC.addKey(keccak256(abi.encode(address(hsmIssuer))), 2, 1);

        vm.prank(address(hsmIssuer));
        didKYC.execute(wallet2, 1 ether, _data);

        uint256 balanceWallet2 = wallet2.balance;
        console.log(balanceWallet2);

        uint256 balanceContract3 = address(didKYC).balance;
        console.log(balanceContract3);

        ///@dev notes:
        /*Autorizacao de executar acoes em sua identidade.
        Porem, MUITO CUIDADO! sendo que qualquer um conseguira executar essa funcionalidade
        deve ser alterado o seu contrato para que tenha regras relacionado ao execute
        */
    }

    function testExecuteMint() public {
        //teste de execucao da identidade em outro contrato de mint a token:
        uint256 amount = 1000;

        // Codificando a chamada da função mint(address,uint256)
        bytes memory data = abi.encodeWithSignature("mint(address,uint256)", wallet1, amount);

        vm.prank(hsm);
        didKYC.addKey(keccak256(abi.encode(address(wallet1))), 2, 1);

        // Chamar a função execute do contrato de identidade
        vm.prank(address(wallet1)); 
        uint256 executionId = didKYC.execute(address(token), 0, data);
        console.log("executId: ", executionId);

        // Verifique se a execução foi realizada com sucesso
        (bool success,) = address(token).call(data);
        require(success, "Mint failed");

        // (Opcional) Verificar o saldo após a mintagem
        uint256 balance = token.balanceOf(wallet1);
        uint256 balancedidKYC = token.balanceOf(address(didKYC));
        console.log("balance didKYC:", balancedidKYC);
        console.log("balance wallet1:", balance);
        //assertEq(balance, amount);
    }

    //auxiliar de assinatura
    function setSig(address _hsm, string memory _make, string memory _KYC_json)public returns (bytes memory sig, bytes memory data){ 
        uint256 pk;
        (_hsm, pk) = makeAddrAndKey(_make);

        //dados que devem ser criptografados pq serão públicos
        bytes memory dataKYC = abi.encode(wallet1, _KYC_json);
        // Geração do dataHash e prefixedHash
        bytes32 dataHash = keccak256(abi.encode(address(didKYC), KYC_CLAIM_TOPIC, dataKYC));
        bytes32 prefixedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", dataHash));

        // Assinatura do prefixedHash
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, prefixedHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        return (signature,dataKYC);
    }
}
