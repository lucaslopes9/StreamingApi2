<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;
	
$AcessoUser = InfoUser(3);
if($AcessoUser == 1){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
	 
$status = (isset($_POST['status'])) ? $_POST['status'] : '';

	if(empty($status)){
		echo MensagemAlerta($_TRA['erro'], "Status é um campo obrigatório!", "danger");
	}
	else{
				
	$SQL = "UPDATE captcha SET
			status = :status";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':status', $status, PDO::PARAM_STR); 
	$SQL->execute(); 
		
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], "Captcha configurado com sucesso!
	", "success", "index.php?p=config-captcha");
	}
		
		
			}
		}
	}
}
?>