<?php
	include("conexao.php");
	include_once("functions.php");
	include_once(Idioma(1));

	if(ProtegePag() == true){
	global $_TRA;
	
	$ColunaAdmin = array('RevBloquear', 'RevDesativar', 'RevExcluir');
	$VerificarAcesso = VerificarAcesso('rev', $ColunaAdmin);

	$AdminBloquear = $VerificarAcesso[0];
	$AdminDesativar = $VerificarAcesso[1];
	$AdminExcluir = $VerificarAcesso[2];
 
	if( ($AdminBloquear == 'S') || ($AdminDesativar == 'S') || ($AdminExcluir == 'S') ){

	$CadUserOnline = InfoUser(2);
	$ArvoreAdminOnline = ArvoreAdminRev($CadUserOnline);
	
	if ($_SERVER['REQUEST_METHOD'] == 'POST') {

	$camposMarcados = (isset($_POST['camposMarcados'])) ? $_POST['camposMarcados'] : '';
	$status = (isset($_POST['status'])) ? $_POST['status'] : '';
	$rev = (isset($_POST['rev'])) ? $_POST['rev'] : '';
	$EditarPremium = (isset($_POST['EditarPremium'])) ? $_POST['EditarPremium'] : '';
	$EditarPerfil = (isset($_POST['EditarPerfil'])) ? $_POST['EditarPerfil'] : '';
	$EditarValorCobrado = (isset($_POST['EditarValorCobrado'])) ? ConverterDinheiro($_POST['EditarValorCobrado']) : '';
	$EditarValorCobradoCab = (isset($_POST['EditarValorCobradoCab'])) ? ConverterDinheiro($_POST['EditarValorCobradoCab']) : '';
	
	if( empty($EditarPerfil) && ($status == "perfil") ){
		echo MensagemAlerta($_TRA['erro'], $_TRA['sepmup'], "danger");
	}	
	elseif( empty($EditarPremium) && ($status == "vencimento") ){
		echo MensagemAlerta($_TRA['erro'], $_TRA['dpeuco'], "danger");
	}
	elseif(empty($camposMarcados)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['spmuu'], "danger");
	}
	elseif(empty($status)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['spmuo'], "danger");
	}
	else{	
		
		if( $status == "vencimento" ){
			$EditarPremium = ConverterData($EditarPremium, 2);
			$EditarPremium = strtotime($EditarPremium);
		}
		elseif( $status == "perfil" ){
			$profile = trim(implode("", $EditarPerfil));
			$EditarPerfil = empty($profile) ? "" : $profile;
		}
	
		for($i = 0; $i < count($camposMarcados); $i++){
	
			if(!in_array($camposMarcados[$i], $ArvoreAdminOnline)) {
				echo MensagemAlerta($_TRA['erro'], str_replace("USER_TAG",$camposMarcados[$i],$_TRA['npounpav']), "danger");
				exit;
			}
			else{
				
				if( $status == "valores" ){
						$SQL = "UPDATE rev SET
								ValorCobrado = :ValorCobrado,
								ValorCobradoCabo = :ValorCobradoCabo
            					WHERE usuario = :usuario";
						$SQL = $painel_user->prepare($SQL);
						$SQL->bindParam(':ValorCobrado', $EditarValorCobrado, PDO::PARAM_STR);
						$SQL->bindParam(':ValorCobradoCabo', $EditarValorCobradoCab, PDO::PARAM_STR);
						$SQL->bindParam(':usuario', $camposMarcados[$i], PDO::PARAM_STR);
						$SQL->execute();
				}
				elseif( $status == "perfil" ){
						$SQL = "UPDATE rev SET
								perfil = :perfil
            					WHERE usuario = :usuario";
						$SQL = $painel_user->prepare($SQL);
						$SQL->bindParam(':perfil', $EditarPerfil, PDO::PARAM_STR);
						$SQL->bindParam(':usuario', $camposMarcados[$i], PDO::PARAM_STR);
						$SQL->execute();
				}
				elseif( $status == "arvore" ){
						if($rev != $camposMarcados[$i]){
						$SQL = "UPDATE rev SET
								CadUser = :CadUser
            					WHERE usuario = :usuario";
						$SQL = $painel_user->prepare($SQL);
						$SQL->bindParam(':CadUser', $rev, PDO::PARAM_STR);
						$SQL->bindParam(':usuario', $camposMarcados[$i], PDO::PARAM_STR);
						$SQL->execute();
						}
				}
				elseif( $status == "vencimento" ){
						
						$PrePago = "N";
						$Cota = 0;
						$SQL = "UPDATE rev SET
								data_premio = :data_premio,
								PrePago = :PrePago,
								Cota = :Cota,
								CotaDias = :CotaDias
            					WHERE usuario = :usuario";
						$SQL = $painel_user->prepare($SQL);
						$SQL->bindParam(':data_premio', $EditarPremium, PDO::PARAM_STR);
						$SQL->bindParam(':PrePago', $PrePago, PDO::PARAM_STR);
						$SQL->bindParam(':Cota', $Cota, PDO::PARAM_STR);
						$SQL->bindParam(':CotaDias', $Cota, PDO::PARAM_STR);
						$SQL->bindParam(':usuario', $camposMarcados[$i], PDO::PARAM_STR);
						$SQL->execute();
				}
				elseif( ($status == "bloquear") && ($AdminBloquear == 'S')){
					BloquearDesbloquearArvore($camposMarcados[$i], "S");
					
					$bloqueado = "S";
					$SQL = "UPDATE rev SET
					bloqueado = :bloqueado
           			WHERE usuario = :usuario";
					$SQL = $painel_user->prepare($SQL);
					$SQL->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR); 
					$SQL->bindParam(':usuario', $camposMarcados[$i], PDO::PARAM_STR); 
					$SQL->execute(); 
				}
				elseif( ($status == "desbloquear") && ($AdminBloquear == 'S')){
					BloquearDesbloquearArvore($camposMarcados[$i], "N");
	
					$bloqueado = "N";
					$SQL = "UPDATE rev SET
					bloqueado = :bloqueado
            		WHERE usuario = :usuario";
					$SQL = $painel_user->prepare($SQL);
					$SQL->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR); 
					$SQL->bindParam(':usuario', $camposMarcados[$i], PDO::PARAM_STR); 
					$SQL->execute();	
				}
				elseif( ($status == "ativar") && ($AdminDesativar == 'S')){
					DesativarAtivarArvore($camposMarcados[$i], "N");
	
					$inativo = "N";
					$SQL = "UPDATE rev SET
					inativo = :inativo
            		WHERE usuario = :usuario";
					$SQL = $painel_user->prepare($SQL);
					$SQL->bindParam(':inativo', $inativo, PDO::PARAM_STR); 
					$SQL->bindParam(':usuario', $camposMarcados[$i], PDO::PARAM_INT); 
					$SQL->execute(); 
				}
				elseif( ($status == "desativar") && ($AdminDesativar == 'S')){
					DesativarAtivarArvore($camposMarcados[$i], "S");
	
					$inativo = "S";
					$SQL = "UPDATE rev SET
					inativo = :inativo
           			WHERE usuario = :usuario";
					$SQL = $painel_user->prepare($SQL);
					$SQL->bindParam(':inativo', $inativo, PDO::PARAM_STR); 
					$SQL->bindParam(':usuario', $camposMarcados[$i], PDO::PARAM_INT); 
					$SQL->execute();
					
				}
				elseif( ($status == "excluir") && ($AdminExcluir == 'S') ){
					//Administrador 
					$ArvoreAdmin = ArvoreAdmin($camposMarcados[$i]);
					if(!empty($ArvoreAdmin)){
						for($is = 0; $is < count($ArvoreAdmin); $is++){
						$ExcluirPorUsuario = ExcluirPorUsuario($ArvoreAdmin[$is]);
						}
					}
	
					//Revendedor 
					$ArvoreRev = ArvoreRev($camposMarcados[$i]);
					if(!empty($ArvoreRev)){
						for($is = 0; $is < count($ArvoreRev); $is++){
						$ExcluirPorUsuario = ExcluirPorUsuario($ArvoreRev[$is]);
						}
					}
	
					//Usuário 
					$ArvoreUser = ArvoreUser($camposMarcados[$i]);
					if(!empty($ArvoreUser)){
						for($is = 0; $is < count($ArvoreUser); $is++){
						$ExcluirPorUsuario = ExcluirPorUsuario($ArvoreUser[$is]);
						}
					}
	
					//Teste 
					$ArvoreTeste = ArvoreTeste($camposMarcados[$i]);
					if(!empty($ArvoreTeste)){
						for($is = 0; $is < count($ArvoreTeste); $is++){
						$ExcluirPorUsuario = ExcluirPorUsuario($ArvoreTeste[$is]);
						}
					}
	
					//Deletar Usuário
					$ExcluirPorUsuario = ExcluirPorUsuario($camposMarcados[$i]);
					$SQL = "DELETE FROM rev WHERE usuario = :usuario";
					$SQL = $painel_user->prepare($SQL);
					$SQL->bindParam(':usuario', $camposMarcados[$i], PDO::PARAM_STR); 
					$SQL->execute(); 
				}
			}
		}
	
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger", "index.php?p=revendedor");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['arcs'], "success", "index.php?p=revendedor");
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