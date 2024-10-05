<?php
include_once("functions.php");
include("conexao.php");

$InicioXML = 1000;
$LeituraTxt = LeituraTxt();
$FinalXML = empty($LeituraTxt) ? 0 : $LeituraTxt;

$RetTable = empty($FinalXML) ? "LIMIT 0, ".$InicioXML."" : "LIMIT ".$FinalXML.", ".$InicioXML."";

$SQL = "(SELECT CadUser, usuario, data_premio, xml, bloqueado FROM usuario) UNION ALL (SELECT CadUser, usuario, data_premio, xml, bloqueado FROM teste) ORDER BY usuario ASC ".$RetTable;
$SQL = $painel_user->prepare($SQL);
$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR);
$SQL->execute();

$DataAtual = strtotime(date('Y-m-d'));

while($LnAll = $SQL->fetch()){
	$CadUser = $LnAll['CadUser'];
	$usuario = $LnAll['usuario'];
	$data_premio = $LnAll['data_premio'];
	$xml = $LnAll['xml'];
	$bloqueado = $LnAll['bloqueado'];
	$VerificarBlockArvore = VerificarBlockArvore($CadUser, $usuario);
				
	if( ($bloqueado == "S") && ($xml == "S") ){
		UpdateUserXML($usuario, 'N');
	}
	elseif( ($data_premio < $DataAtual) && ($xml == "S") ){
		UpdateUserXML($usuario, 'N');
	}
	elseif( ($VerificarBlockArvore == 1) && ($xml == "S") ){
		UpdateUserXML($usuario, 'N');
	}
	elseif( ($VerificarBlockArvore == 3) && ($xml == "S") ){
		UpdateUserXML($usuario, 'N');
	}
	elseif( ($VerificarBlockArvore == 1) && ($xml == "N") ){
		continue;
	}
	elseif( ($VerificarBlockArvore == 3) && ($xml == "N") ){
		continue;
	}
	elseif( ($data_premio > $DataAtual) && ($bloqueado == "N") && ($xml == "N") || ($data_premio == $DataAtual) && ($bloqueado == "N") && ($xml == "N") ){
		UpdateUserXML($usuario, 'S');
	}	
}

	$SQL = "(SELECT id FROM usuario) UNION ALL (SELECT id FROM teste)";
	$SQL = $painel_user->prepare($SQL);
	$SQL->execute();
	$TotalSQL = count($SQL->fetchAll());

	$FinalXML = $FinalXML + $InicioXML;
		if($FinalXML > $TotalSQL){
			$FinalXML = 0;
		}
	CriarTxt($FinalXML);
?>