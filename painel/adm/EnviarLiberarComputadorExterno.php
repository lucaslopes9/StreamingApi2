<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
		
	$ConfSMS = (isset($_POST['ConfSMS'])) ? $_POST['ConfSMS'] : 2;
	$CodigoSMS = (isset($_POST['CodigoSMS'])) ? $_POST['CodigoSMS'] : '';
	$Hostname = getenv('USERNAME');	
	$gethostbyaddr = gethostbyaddr($_SERVER['REMOTE_ADDR']);
	$ip = $_SERVER['REMOTE_ADDR'];
	
	$CadUser = InfoUser(2);
	$SQLCel = "SELECT celular FROM ".SelectTabela()." WHERE usuario = :usuario";
	$SQLCel = $painel_user->prepare($SQLCel);
	$SQLCel->bindParam(':usuario', $CadUser, PDO::PARAM_STR);
	$SQLCel->execute();
	$LnCel = $SQLCel->fetch();
	$celular = $LnCel['celular'];
	
	//Verificar Computador Cadastrado ativo
	$ativo = "S";
	$SQLComp = "SELECT id FROM liberarcomputador WHERE CadUser = :CadUser AND codigo = :codigo AND ativo = :ativo";
	$SQLComp = $painel_geral->prepare($SQLComp);
	$SQLComp->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLComp->bindParam(':codigo', $CodigoSMS, PDO::PARAM_STR);
	$SQLComp->bindParam(':ativo', $ativo, PDO::PARAM_STR);
	$SQLComp->execute();
	$TotalComp = count($SQLComp->fetchAll());
	
	//Verificar Computador Cadastrado desativado
	$ativo = "N";
	$SQLCompD = "SELECT id FROM liberarcomputador WHERE CadUser = :CadUser AND gethostbyaddr = :gethostbyaddr AND computador = :computador AND ip = :ip AND ativo = :ativo";
	$SQLCompD = $painel_geral->prepare($SQLCompD);
	$SQLCompD->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLCompD->bindParam(':gethostbyaddr', $gethostbyaddr, PDO::PARAM_STR);
	$SQLCompD->bindParam(':computador', $Hostname, PDO::PARAM_STR);
	$SQLCompD->bindParam(':ip', $ip, PDO::PARAM_STR);
	$SQLCompD->bindParam(':ativo', $ativo, PDO::PARAM_STR);
	$SQLCompD->execute();
	$TotalCompD = count($SQLCompD->fetchAll());
		
	$VerificarSMSLibComputador = VerificarSMSLibComputador($CadUser);
		
	if($TotalCompD > 0){
		
		if( !empty($CodigoSMS) && $ConfSMS == 1){
			$ativo = "N";
			$SQLCompC = "SELECT id FROM liberarcomputador WHERE CadUser = :CadUser AND ativo = :ativo AND codigo = :codigo";
			$SQLCompC = $painel_geral->prepare($SQLCompC);
			$SQLCompC->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
			$SQLCompC->bindParam(':ativo', $ativo, PDO::PARAM_STR);
			$SQLCompC->bindParam(':codigo', $CodigoSMS, PDO::PARAM_STR);
			$SQLCompC->execute();
			$TotalCompC = count($SQLCompC->fetchAll());
		}			
			if( empty($CodigoSMS) && $ConfSMS == 2){

				  echo MensagemAlerta($_TRA['atencao'], $_TRA['ucsjfeposcpfaordseiecsecnio'], "warning");
				  
			}
			elseif( ($TotalCompC < 1) && !empty($CodigoSMS) && $ConfSMS == 1){
				  
				  echo MensagemAlerta($_TRA['atencao'], $_TRA['csncone'], "danger");
				  
			}
			elseif( empty($CodigoSMS) && $ConfSMS == 1){
				  
				  echo MensagemAlerta($_TRA['atencao'], $_TRA['cseuco'], "danger");
				  
			}
			else{
			
			$ativo = "S";
			$SQL = "UPDATE liberarcomputador SET
			ativo = :ativo
            WHERE CadUser = :CadUser AND codigo = :codigo";
			$SQL = $painel_geral->prepare($SQL);                                  
			$SQL->bindValue(':ativo', $ativo); 
			$SQL->bindValue(':CadUser', $CadUser); 
			$SQL->bindValue(':codigo', $CodigoSMS); 
			$SQL->execute();
			
			unset($_SESSION['LCcomputador']);
			unset($_SESSION['LCLiberarComputador']);
			setcookie('ComputadorLiberado', md5($CodigoSMS.$_SERVER['REMOTE_ADDR']), time()+3600*24*365*2, '/');
			
			echo MensagemAlerta($_TRA['sucesso'], $_TRA['clcs'], "success");
			echo Redirecionar('index.php?p=inicio');
				  
			}
	}	
	elseif($TotalComp > 0){
		echo "<div class=\"form-group\"><div class=\"col-md-12\"><div class=\"alert alert-danger\" role=\"alert\">
                  	<button type=\"button\" class=\"close\" data-dismiss=\"alert\"><span aria-hidden=\"true\">×</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                    	<strong>".$_TRA['atencao']."!</strong> ".$_TRA['ecjesl']."
         </div></div></div>";
				  
	}	
	elseif(empty($celular)){
		
		 echo MensagemAlerta($_TRA['atencao'], $_TRA['vnpundcc'], "danger");
		
	}
	elseif(is_numeric(LimparCelular($celular)) == false){
		
		echo MensagemAlerta($_TRA['atencao'], $_TRA['cdcan'], "danger");
	
	}
	elseif($VerificarSMSLibComputador == 1){
		
		echo MensagemAlerta($_TRA['atencao'], $_TRA['cucdsesa'], "danger");
		
	}
	elseif($VerificarSMSLibComputador == 2){
		
		echo MensagemAlerta($_TRA['atencao'], $_TRA['acsaesbrode'], "danger");
		
	}
	else{
		
	$CodigoLiberacao = CodigoLiberacao();
	$mensagem = $_SERVER['HTTP_HOST'].$_TRA['iocploce'].$CodigoLiberacao;
	$EnviarSMS = EnviarSMS($CadUser, $mensagem, $celular);

	if($EnviarSMS == 1){
		$data = time();
		$SQL = "INSERT INTO liberarcomputador (
			CadUser,
            gethostbyaddr,
            computador,
			ip,
			codigo,
			data
            ) VALUES (
            :CadUser,
            :gethostbyaddr,
            :computador,
			:ip,
			:codigo,
			:data
			)";
		$SQL = $painel_geral->prepare($SQL);
		$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
		$SQL->bindParam(':gethostbyaddr', $gethostbyaddr, PDO::PARAM_STR);
		$SQL->bindParam(':computador', $Hostname, PDO::PARAM_STR);
		$SQL->bindParam(':ip', $ip, PDO::PARAM_STR);
		$SQL->bindParam(':codigo', $CodigoLiberacao, PDO::PARAM_STR);
		$SQL->bindParam(':data', $data, PDO::PARAM_STR);
		$SQL->execute(); 
		
		if(empty($SQL)){
			
			echo MensagemAlerta($_TRA['atencao'], $_TRA['erropro'], "danger");
			
		}
		else{		
			
		
			echo MensagemAlerta($_TRA['atencao'], $_TRA['ucsfeposcioecsecnfopepc'], "info");	
			
		}
	}
	else{
		
		echo MensagemAlerta($_TRA['atencao'], $_TRA['oueaeospfvsnetmt'], "danger");	
		
	}
			
	}
}

}else{
	echo Redirecionar('login.php');
}	

?>