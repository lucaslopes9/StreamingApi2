<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('PagamentoPagSeguro');
$VerificarAcesso = VerificarAcesso('pagamentos', $ColunaAcesso);
$PagamentoPagSeguro = $VerificarAcesso[0];
 
if($PagamentoPagSeguro == 'S'){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {

	$Email = (isset($_POST['Email'])) ? $_POST['Email'] : '';
	$Token = (isset($_POST['Token'])) ? $_POST['Token'] : '';
	$CadUser = InfoUser(2);

	$SQL = "SELECT id, email, token FROM contapagseguro WHERE CadUser = :CadUser";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQL->execute();
	$Total = count($SQL->fetchAll());
	
	if(empty($Email)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['euco'], "danger");
	}
	elseif( substr_count($Email, "@") == 0 || substr_count($Email, ".") == 0) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['dei'], "danger");
	}
	elseif(empty($Token)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['tokeneuco'], "danger");
	}
	elseif($Total > 0){
		echo MensagemAlerta($_TRA['erro'], $_TRA['jeuca'], "danger");
	}
	else{
	
	$SQL = "INSERT INTO contapagseguro (
			CadUser,
            email,
            token
            ) VALUES (
            :CadUser,
            :email,
            :token
			)";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_INT);
	$SQL->bindParam(':email', $Email, PDO::PARAM_INT);
	$SQL->bindParam(':token', $Token, PDO::PARAM_STR);
	$SQL->execute(); 
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['adcs'], "success", "index.php?p=pagseguro");
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