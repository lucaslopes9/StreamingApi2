<?php
include("conexao.php");
include_once("functions.php");

if(ProtegePag() == true){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
 
	$cabecalho = (isset($_POST['cabecalho'])) ? $_POST['cabecalho'] : '';
	$barralateral = (isset($_POST['barralateral'])) ? $_POST['barralateral'] : '';
	$scroll = (isset($_POST['scroll'])) ? $_POST['scroll'] : '';
	$barradireita = (isset($_POST['barradireita'])) ? $_POST['barradireita'] : '';
	$navpersonalizado = (isset($_POST['navpersonalizado'])) ? $_POST['navpersonalizado'] : '';
	$alternarnav = (isset($_POST['alternarnav'])) ? $_POST['alternarnav'] : '';
	
	$_SESSION['cabecalho'] = $cabecalho;
	$_SESSION['barralateral'] = $barralateral;
	$_SESSION['scroll'] = $scroll;
	$_SESSION['barradireita'] = $barradireita;
	$_SESSION['navpersonalizado'] = $navpersonalizado;
	$_SESSION['alternarnav'] = $alternarnav;
	
	$user = InfoUser(2);
	$SQLLeiaute = "SELECT id FROM leiaute WHERE CadUser = :CadUser";
	$SQLLeiaute = $painel_geral->prepare($SQLLeiaute);
	$SQLLeiaute->bindParam(':CadUser', $user, PDO::PARAM_STR); 
	$SQLLeiaute->execute();
	$TotalLeiaute = count($SQLLeiaute->fetchAll());
	
	$user = InfoUser(2);
	if($TotalLeiaute > 0){
	$SQL = "UPDATE leiaute SET
			cabecalho = :cabecalho,
			barralateral = :barralateral,
			scroll = :scroll,
			barradireita = :barradireita,
			navpersonalizado = :navpersonalizado,
			alternarnav = :alternarnav
            WHERE CadUser = :CadUser";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':cabecalho', $cabecalho, PDO::PARAM_INT);
	$SQL->bindParam(':barralateral', $barralateral, PDO::PARAM_INT);
	$SQL->bindParam(':scroll', $scroll, PDO::PARAM_INT);
	$SQL->bindParam(':barradireita', $barradireita, PDO::PARAM_INT);
	$SQL->bindParam(':navpersonalizado', $navpersonalizado, PDO::PARAM_INT);
	$SQL->bindParam(':alternarnav', $alternarnav, PDO::PARAM_INT);
	$SQL->bindParam(':CadUser', $user, PDO::PARAM_STR); 
	$SQL->execute(); 
	}
	else{
	$SQL = "INSERT INTO leiaute (
			CadUser,
			cabecalho,
            barralateral,
            scroll,
			barradireita,
			navpersonalizado,
			alternarnav
            ) VALUES (
			:CadUser,
            :cabecalho, 
            :barralateral, 
            :scroll, 
			:barradireita, 
			:navpersonalizado, 
			:alternarnav
			)";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':CadUser', $user, PDO::PARAM_STR);
	$SQL->bindParam(':cabecalho', $cabecalho, PDO::PARAM_INT);
	$SQL->bindParam(':barralateral', $barralateral, PDO::PARAM_INT);
	$SQL->bindParam(':scroll', $scroll, PDO::PARAM_INT);
	$SQL->bindParam(':barradireita', $barradireita, PDO::PARAM_INT);
	$SQL->bindParam(':navpersonalizado', $navpersonalizado, PDO::PARAM_INT);
	$SQL->bindParam(':alternarnav', $alternarnavs, PDO::PARAM_INT);
	$SQL->execute(); 
	}
		
}

}

?>