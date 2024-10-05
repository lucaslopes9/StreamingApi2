<?php
include("../conexao.php");
include_once("../functions.php");

$caduser = $_GET['caduser'];
$rev = $_GET['rev'];
$status = $_GET['status'];
$perfil = $_GET['perfil'];

$VerificarStatusOnline = VerificarStatusOnline($caduser, $rev, $status, $perfil);
?>
<?php
	for($i=0; $i<count($VerificarStatusOnline); $i++){
										
	$PerfilAtual = "[".$VerificarStatusOnline[$i][4]."]";
	$perfil = SelecionarPerfil($PerfilAtual);
	$SQLUser = "SELECT CadUser, nome FROM usuario WHERE usuario = :usuario";
	$SQLUser = $painel_user->prepare($SQLUser);
	$SQLUser->bindParam(':usuario', $VerificarStatusOnline[$i][0], PDO::PARAM_STR);
	$SQLUser->execute();
	$LnUser = $SQLUser->fetch();

        echo $VerificarStatusOnline[$i][0];
	echo "</br>";

	//$explode = explode(" ",$VerificarStatusOnline[$i][0]);
	//print_r($explode);	
	 //echo('<br> ');																
	}

						  
?>
