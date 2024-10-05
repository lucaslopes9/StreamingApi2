<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('PagamentoContaBancaria');
$VerificarAcesso = VerificarAcesso('pagamentos', $ColunaAcesso);
$PagamentoContaBancaria = $VerificarAcesso[0];
 
if($PagamentoContaBancaria == 'S'){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {

	$Tipo = (isset($_POST['Tipo'])) ? $_POST['Tipo'] : '';
	$Banco = (isset($_POST['Banco'])) ? $_POST['Banco'] : '';
	$Agencia = (isset($_POST['Agencia'])) ? $_POST['Agencia'] : '';
	$Conta = (isset($_POST['Conta'])) ? $_POST['Conta'] : '';
	$Favorecido = (isset($_POST['Favorecido'])) ? $_POST['Favorecido'] : '';
	$Operacao = (isset($_POST['Operacao'])) ? $_POST['Operacao'] : '';
	$CadUser = InfoUser(2);
	
	if(empty($Tipo)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['teuco'], "danger");
	}
	elseif( ($Tipo != "C") && ($Tipo != "P") ){
		echo MensagemAlerta($_TRA['erro'], $_TRA['TipoInvalido'], "danger");
	}
	elseif(empty($Banco)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['bancoeuco'], "danger");
	}
	elseif(empty($Agencia)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['agenciaeuco'], "danger");
	}
	elseif(empty($Conta)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['contaeuco'], "danger");
	}
	elseif(empty($Favorecido)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['favorecidoeuco'], "danger");
	}
	else{
	
	$SQL = "INSERT INTO contabancaria (
			CadUser,
            banco,
            tipo,
			agencia,
			operacao,
			conta,
			favorecido
            ) VALUES (
            :CadUser,
            :banco,
            :tipo,
			:agencia,
			:operacao,
			:conta,
			:favorecido
			)";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQL->bindParam(':banco', $Banco, PDO::PARAM_STR);
	$SQL->bindParam(':tipo', $Tipo, PDO::PARAM_STR);
	$SQL->bindParam(':agencia', $Agencia, PDO::PARAM_STR);
	$SQL->bindParam(':operacao', $Operacao, PDO::PARAM_STR);
	$SQL->bindParam(':conta', $Conta, PDO::PARAM_STR);
	$SQL->bindParam(':favorecido', $Favorecido, PDO::PARAM_STR);
	$SQL->execute(); 
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['adcs'], "success", "index.php?p=contabancaria");
	}
		
		
	}
}

}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}	

?>