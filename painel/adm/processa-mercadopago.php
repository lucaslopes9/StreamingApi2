<?php
include("conexao.php");
include_once("functions.php");
include('forma/mp.php');
if(ProtegePag() == true){

$CadUser = InfoUser(4);
$descricao = empty($_POST['descricao']) ? "" : $_POST['descricao'];
$preco = empty($_POST['preco']) ? "" : trim($_POST['preco']);
$referencia = empty($_POST['referencia']) ? "" : $_POST['referencia'];
$DadosMercadoPago = DadosMercadoPago($CadUser);

$mp = new MP($DadosMercadoPago[0], $DadosMercadoPago[1]);

$preference_data = array(
	"external_reference" => $referencia,
    "items" => array(
       array(
           "title" => $descricao,
		   "description" => $descricao,
           "quantity" => 1,
           "currency_id" => "BRL",
           "unit_price" => floatval($preco)
       )
    )
);

$preference = $mp->create_preference($preference_data);
$redirecionar = $preference['response']['init_point'];

$_SESSION['data_premio'] = "";
echo Redirecionar($redirecionar);

}else{
	echo Redirecionar('login.php');
}	
?>