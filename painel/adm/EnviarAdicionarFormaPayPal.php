<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('PagamentoPayPal');
$VerificarAcesso = VerificarAcesso('pagamentos', $ColunaAcesso);
$PagamentoPayPal = $VerificarAcesso[0];
 
if($PagamentoPayPal == 'S'){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {

	$Email = (isset($_POST['Email'])) ? $_POST['Email'] : '';
	$Senha = (isset($_POST['Senha'])) ? $_POST['Senha'] : '';
	$CadUser = InfoUser(2);

	$SQL = "SELECT id, email, senha FROM contapaypal WHERE CadUser = :CadUser";
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
	elseif(empty($Senha)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['SCO'], "danger");
	}
	elseif($Total > 0){
		echo MensagemAlerta($_TRA['erro'], $_TRA['jeuca'], "danger");
	}
	else{
	
	$SQL = "INSERT INTO contapaypal (
			CadUser,
            email,
            senha
            ) VALUES (
            :CadUser,
            :email,
            :senha
			)";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_INT);
	$SQL->bindParam(':email', $Email, PDO::PARAM_INT);
	$SQL->bindParam(':senha', $Senha, PDO::PARAM_STR);
	$SQL->execute(); 
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['adcs'], "success", "index.php?p=paypal");
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