<?php
include("conexao.php");
include_once("functions.php");

if(ProtegePag() == true){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
 
	$minimizar = $_SESSION['minimizar'] == "S" ? "N" : "S";
	$alternarnav = $_SESSION['minimizar'] == "S" ? 0 : 1;
	
	$user = InfoUser(2);
	$SQLLeiaute = "SELECT id FROM leiaute WHERE CadUser = :CadUser";
	$SQLLeiaute = $painel_geral->prepare($SQLLeiaute);
	$SQLLeiaute->bindParam(':CadUser', $user, PDO::PARAM_STR); 
	$SQLLeiaute->execute();
	$TotalLeiaute = count($SQLLeiaute->fetchAll());

	$user = InfoUser(2);
	if($TotalLeiaute > 0){
	$SQL = "UPDATE leiaute SET
			minimizar = :minimizar
            WHERE CadUser = :CadUser";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':minimizar', $minimizar, PDO::PARAM_STR);
	$SQL->bindParam(':CadUser', $user, PDO::PARAM_STR); 
	$SQL->execute(); 
	}
	else{
	$SQL = "INSERT INTO leiaute (
			CadUser,
			alternarnav,
			minimizar
            ) VALUES (
			:CadUser,
			:alternarnav,
            :minimizar
			)";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':CadUser', $user, PDO::PARAM_STR);
	$SQL->bindParam(':alternarnav', $alternarnav, PDO::PARAM_INT);
	$SQL->bindParam(':minimizar', $minimizar, PDO::PARAM_STR);
	$SQL->execute(); 
	}
	
	$_SESSION['alternarnav'] = $alternarnav;
	$_SESSION['minimizar'] = $minimizar;
		
}

}

?>