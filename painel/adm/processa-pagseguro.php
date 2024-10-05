<?php
include("conexao.php");
include_once("functions.php");
include('PagSeguroLibrary/PagSeguroLibrary.php');
if(ProtegePag() == true){

$CadUser = InfoUser(4);
$descricao = empty($_POST['descricao']) ? "" : $_POST['descricao'];
$preco = empty($_POST['preco']) ? "" : trim($_POST['preco']);
$preco = number_format($preco, 2, '.', '');
$referencia = empty($_POST['referencia']) ? "" : $_POST['referencia'];
$DadosPagSeguro = DadosPagSeguro($CadUser);

$paymentRequest = new PagSeguroPaymentRequest(); 
$paymentRequest->addItem($descricao, $descricao, 1, $preco); 

$paymentRequest->setCurrency("BRL");  
$paymentRequest->setShippingType(1); 
$paymentRequest->setReference($referencia);  

$credentials = PagSeguroConfig::getAccountCredentials($DadosPagSeguro[0], $DadosPagSeguro[1]);
  
// fazendo a requisição a API do PagSeguro pra obter a URL de pagamento  
$url_pag_seguro = $paymentRequest->register($credentials);  
	
$_SESSION['data_premio'] = "";
echo Redirecionar($url_pag_seguro);

}else{
	echo Redirecionar('login.php');
}	
?>