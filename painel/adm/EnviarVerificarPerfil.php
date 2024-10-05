<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$UserOnline = InfoUser(2);
$Revendedor = InfoUser(4);

	//Árvore
	$ArvoreAdmin = ArvoreAdminExibir($Revendedor);
	$ArvoreAdmin = array_reverse($ArvoreAdmin);
	$ArvoreAdmin[] = $UserOnline;
	$ArvoreAdmin[] = $Revendedor;
	$ArvoreAdmin = array_reverse($ArvoreAdmin);
	$ArvoreAdmin = implode(",",$ArvoreAdmin);
	
	$ArvoreRev = ArvoreRevExibir($Revendedor);
	$ArvoreRev = array_reverse($ArvoreRev);
	$ArvoreRev[] = $UserOnline;
	$ArvoreRev[] = $Revendedor;
	$ArvoreRev = array_reverse($ArvoreRev);
	$ArvoreRev = implode(",",$ArvoreRev);
	//Árvore

	$SQLUser = "SELECT perfil FROM ".SelectTabela()." WHERE usuario = :usuario";
	$SQLUser = $painel_user->prepare($SQLUser);
	$SQLUser->bindParam(':usuario', $UserOnline, PDO::PARAM_STR);
	$SQLUser->execute();
	$LnUser = $SQLUser->fetch();
	$perfil = $LnUser['perfil'];
	$perfil = str_replace("][","],[",$perfil);
	
	//Verificar o ID do Painel no Perfil
	$bloqueado = "N";
	$SQLPerfil = "SELECT id, nome, url, porta, valorcsp FROM perfil WHERE FIND_IN_SET(valorcsp,:valorcsp) AND bloqueado = :bloqueado";
	$SQLPerfil = $painel_geral->prepare($SQLPerfil);
	$SQLPerfil->bindParam(':valorcsp', $perfil, PDO::PARAM_STR);
	$SQLPerfil->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
	$SQLPerfil->execute();
	$TotalPerfil = count($SQLPerfil->fetchAll());
	
	$_SESSION['OperadoraPerfil'] = array();
	
	if($TotalPerfil > 0){
	
	echo "

								<table class=\"table table-striped\">
                                            <thead>
                                                <tr>
                                                    <th><center>".$_TRA['Operadora']."</center></th>
                                                    <th><center>".$_TRA['Url']."</center></th>
                                                    <th><center>".$_TRA['Porta']."</center></th>
                                                </tr>
                                            </thead>
                                            <tbody>";
											
											$SQLPerfil->execute();
											while($LnPerfil = $SQLPerfil->fetch()){
												
											$UrlPerfil = $LnPerfil['url'];
											$UrlNome = $LnPerfil['nome'];
											$UrlPorta = $LnPerfil['porta'];
											
											$MaskPerfil = MaskPerfil($UserOnline, $LnPerfil['id']);
											
											$nome = $MaskPerfil[0];
											$url = $MaskPerfil[1];
											$porta = $MaskPerfil[2];
											
											//Verificar se existe máscara com o valor do CSP
												$bloqueado = "N";
												$SQLM = "SELECT id FROM perfil WHERE valorcsp = :valorcsp AND bloqueado = :bloqueado";
												$SQLM = $painel_geral->prepare($SQLM);
												$SQLM->bindParam(':valorcsp', $LnPerfil['valorcsp'], PDO::PARAM_STR);
												$SQLM->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
												$SQLM->execute();
												
												$idperfil = "";
												while($LnM = $SQLM->fetch()){
													$idperfil .= $LnM['id'].",";
												}
												$idperfil = substr($idperfil, -0, -1);
												
												$SQLMk = "SELECT id FROM mascaraurl WHERE FIND_IN_SET(perfil,:perfil) AND bloqueado = :bloqueado AND FIND_IN_SET(CadUser,:CadUser) OR FIND_IN_SET(perfil,:perfil) AND bloqueado = :bloqueado AND FIND_IN_SET(CadUser,:CadUserAdmin)";
												$SQLMk = $painel_geral->prepare($SQLMk);
												$SQLMk->bindParam(':perfil', $idperfil, PDO::PARAM_STR);
												$SQLMk->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
												$SQLMk->bindParam(':CadUser', $ArvoreRev, PDO::PARAM_STR);
												$SQLMk->bindParam(':CadUserAdmin', $ArvoreAdmin, PDO::PARAM_STR);
												$SQLMk->execute();
												$TotalMk = count($SQLMk->fetchAll());
											//Exit	
																																	
											if( ($UrlPerfil == $url) && ($UrlNome == $nome) && ($UrlPorta == $porta) && ($TotalMk > 0) ){
												continue;
											}
						
											$ArrayPerfil = array($nome, $url, $porta);
											
											array_push($_SESSION['OperadoraPerfil'], $ArrayPerfil);
											
											echo "
                                                <tr>
                                                    <td><center>".$nome."</center></td>
                                                    <td><center>".$url."</center></td>
                                                    <td><center>".$porta."</center></td>
                                                </tr>
												";
											
											}
											echo "
                                            </tbody>
                                  </table>

";

	}
	else{
	
	echo "<center>".$_TRA['noe']."</center>";
		
	}
	
	
	
}else{
	echo Redirecionar('login.php');
}	
?>