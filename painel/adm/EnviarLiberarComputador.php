<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('OpcoesLiberarComputador');
$VerificarAcesso = VerificarAcesso('opcoes', $ColunaAcesso);
$OpcoesLiberarComputador = $VerificarAcesso[0];

if($OpcoesLiberarComputador == 'S'){

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
			
		echo "<form id=\"validate\" role=\"form\" class=\"AdicionarLiberarComputador form-horizontal\" action=\"javascript:MDouglasMS();\">";
		
			$ExibirForm = "<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['cs']."</label>
                            	<div class=\"col-md-9\"> 
									<input id=\"CodigoSMS\" name=\"CodigoSMS\" type=\"text\" class=\"form-control\">
									<input id=\"ConfSMS\" name=\"ConfSMS\" type=\"hidden\" value=\"1\">
                                </div>
                        </div>";
			
			if( empty($CodigoSMS) && $ConfSMS == 2){
				echo "<div class=\"form-group\"><div class=\"col-md-12\"><div class=\"alert alert-warning\" role=\"alert\">
                  	<button type=\"button\" class=\"close\" data-dismiss=\"alert\"><span aria-hidden=\"true\">×</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                    	<strong>".$_TRA['atencao']."!</strong> ".$_TRA['ucsjfeposc']."
                  </div></div></div>";
				echo $ExibirForm;
			}
			elseif( ($TotalCompC < 1) && !empty($CodigoSMS) && $ConfSMS == 1){
				echo "<div class=\"form-group\"><div class=\"col-md-12\"><div class=\"alert alert-danger\" role=\"alert\">
                  	<button type=\"button\" class=\"close\" data-dismiss=\"alert\"><span aria-hidden=\"true\">×</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                    	<strong>".$_TRA['atencao']."!</strong> ".$_TRA['csncone']."
                  </div></div></div>";
				echo $ExibirForm;
			}
			elseif( empty($CodigoSMS) && $ConfSMS == 1){
				echo "<div class=\"form-group\"><div class=\"col-md-12\"><div class=\"alert alert-danger\" role=\"alert\">
                  	<button type=\"button\" class=\"close\" data-dismiss=\"alert\"><span aria-hidden=\"true\">×</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                    	<strong>".$_TRA['atencao']."!</strong> ".$_TRA['cseuco']."
                  </div></div></div>";
				 echo $ExibirForm;
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
				
			echo "<div class=\"form-group\"><div class=\"col-md-12\"><div class=\"alert alert-success\" role=\"alert\">
                  	<button type=\"button\" class=\"close\" data-dismiss=\"alert\"><span aria-hidden=\"true\">×</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                    	<strong>".$_TRA['sucesso']."!</strong> ".$_TRA['clcs']."
                  </div></div></div>";
				  
			}
            echo "
			</form>";
	}
	elseif($TotalComp > 0){
		echo "<div class=\"form-group\"><div class=\"col-md-12\"><div class=\"alert alert-danger\" role=\"alert\">
                  	<button type=\"button\" class=\"close\" data-dismiss=\"alert\"><span aria-hidden=\"true\">×</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                    	<strong>".$_TRA['atencao']."!</strong> ".$_TRA['ecjesl']."
         </div></div></div>";
				  
	}	
	elseif(empty($celular)){
		echo "<div class=\"form-group\"><div class=\"col-md-12\"><div class=\"alert alert-danger\" role=\"alert\">
                  	<button type=\"button\" class=\"close\" data-dismiss=\"alert\"><span aria-hidden=\"true\">×</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                    	<strong>".$_TRA['atencao']."!</strong> ".$_TRA['vnpundcc']."
         </div></div></div>";
	}
	elseif(is_numeric(LimparCelular($celular)) == false){
		echo "<div class=\"form-group\"><div class=\"col-md-12\"><div class=\"alert alert-danger\" role=\"alert\">
                  	<button type=\"button\" class=\"close\" data-dismiss=\"alert\"><span aria-hidden=\"true\">×</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                    	<strong>".$_TRA['atencao']."!</strong> ".$_TRA['cdcan']."
         </div></div></div>";
	}
	elseif($VerificarSMSLibComputador == 1){
		echo "<div class=\"form-group\"><div class=\"col-md-12\"><div class=\"alert alert-danger\" role=\"alert\">
                  	<button type=\"button\" class=\"close\" data-dismiss=\"alert\"><span aria-hidden=\"true\">×</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                    	<strong>".$_TRA['atencao']."!</strong> ".$_TRA['cucdsesa']."
         </div></div></div>";
	}
	elseif($VerificarSMSLibComputador == 2){
		echo "<div class=\"form-group\"><div class=\"col-md-12\"><div class=\"alert alert-danger\" role=\"alert\">
                  	<button type=\"button\" class=\"close\" data-dismiss=\"alert\"><span aria-hidden=\"true\">×</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                    	<strong>".$_TRA['atencao']."!</strong> ".$_TRA['acsaesbrode']."
         </div></div></div>";
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
			
			echo "<div class=\"form-group\"><div class=\"col-md-12\"><div class=\"alert alert-danger\" role=\"alert\">
                  	<button type=\"button\" class=\"close\" data-dismiss=\"alert\"><span aria-hidden=\"true\">×</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                    	<strong>".$_TRA['atencao']."!</strong> ".$_TRA['erropro']."
         </div></div></div>";
			
		}
		else{			
			
			echo "<form id=\"validate\" role=\"form\" class=\"AdicionarLiberarComputador form-horizontal\" action=\"javascript:MDouglasMS();\">";
			
						echo "<div class=\"form-group\"><div class=\"col-md-12\"><div class=\"alert alert-info\" role=\"alert\">
                  	<button type=\"button\" class=\"close\" data-dismiss=\"alert\"><span aria-hidden=\"true\">×</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                    	<strong>".$_TRA['atencao']."!</strong> ".$_TRA['ucsfeposcioecsecel']."
                  </div></div></div>";
                     
                       echo " <div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['cs']."</label>
                            	<div class=\"col-md-9\"> 
									<input id=\"CodigoSMS\" name=\"CodigoSMS\" type=\"text\" class=\"form-control\">
									<input id=\"ConfSMS\" name=\"ConfSMS\" type=\"hidden\" value=\"1\">
                                </div>
                        </div>
						
				</form>";
		}
	}
	else{
		
		echo "<div class=\"form-group\"><div class=\"col-md-12\"><div class=\"alert alert-danger\" role=\"alert\">
                  	<button type=\"button\" class=\"close\" data-dismiss=\"alert\"><span aria-hidden=\"true\">×</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                    	<strong>".$_TRA['atencao']."!</strong> ".$_TRA['oueaeospfvsnetmt']."
         </div></div></div>";
		
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