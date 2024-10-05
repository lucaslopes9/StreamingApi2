<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;
$idioma = empty($_COOKIE['idioma']) ? "br" : $_COOKIE['idioma'];

$VerificarInfoOnline = VerificarInfoOnline();
$usuario = InfoUser(2);
$ExibirNome = empty($VerificarInfoOnline[0]) && empty($VerificarInfoOnline[1]) ? $usuario : $VerificarInfoOnline[0]."&nbsp;".$VerificarInfoOnline[1];
$Foto = Foto($VerificarInfoOnline[3]);

$DataNascimento = empty($VerificarInfoOnline[5]) ? "" : ConverterData($VerificarInfoOnline[5], 1);
$DataCadastro = empty($VerificarInfoOnline[6]) ? "" : ConverterData($VerificarInfoOnline[6], 3);

$status = 1;
$SQLAcesso = "SELECT ip, data FROM registro_acesso WHERE CadUser = :CadUser AND status = :status ORDER by data DESC";
$SQLAcesso = $painel_geral->prepare($SQLAcesso);
$SQLAcesso->bindParam(':CadUser', $usuario, PDO::PARAM_STR);
$SQLAcesso->bindParam(':status', $status, PDO::PARAM_INT);
$SQLAcesso->execute();
$LnUser = $SQLAcesso->fetch();
?>
<link rel="stylesheet" type="text/css" href="css/cropper/cropper.min.css"/>

<script type='text/javascript'> 

$(function(){  
 $("button.AlterarUser").click(function() { 
		
		var Data = $(".FormAlterarUser").serialize();
		
		$('#StatusAlterarUser').html("<center><img src=\"img/owl/AjaxLoader.gif\"><br><br></center>");
		
		$.post('EnviarAlterarUser.php', Data, function(resposta) {
				$("#StatusAlterarUser").html('');
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
		});
	});
});

$(function(){  
 $("button.AlterarSenha").click(function() { 
		
		var Data = $(".AlterarSenha").serialize();
		
		$('#StatusAlterarSenha').html("<center><img src=\"img/owl/AjaxLoader.gif\"><br><br></center>");
		
		$.post('EnviarAlterarSenha.php', Data, function(resposta) {
				$("#StatusAlterarSenha").html('');
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
		});
	});
});

$(function(){
	$("button.EditarPerfil").click(function() { 
		
		var Data = $(".EditarProfile").serialize();
		
		$('#StatusEditarPerfil').html("<center><img src=\"img/owl/AjaxLoader.gif\"><br><br></center>");
		
		$.post('EnviarEditarPerfil.php', Data, function(resposta) {
				$("#StatusEditarPerfil").html('');
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
		});
	});
});

$(function(){
	$("button.EditarPerfilEmail").click(function() { 
		
		var Data = $(".EditarEmail").serialize();
		
		$('#StatusEditarEmail').html("<center><img src=\"img/owl/AjaxLoader.gif\"><br><br></center>");
		
		$.post('EnviarEditarEmail.php', Data, function(resposta) {
				$("#StatusEditarEmail").html('');
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
		});
	});
});
</script>


<!-- START BREADCRUMB -->
                <ul class="breadcrumb">
                    <li class="active"><?php echo $_TRA['Perfil']; ?></li>
                </ul>
                <!-- END BREADCRUMB -->  
                
                <!-- PAGE TITLE -->
                <div class="page-title">                    
                    <h2><span class="fa fa-cogs"></span> <?php echo $_TRA['ep']; ?></h2>
                </div>
                <!-- END PAGE TITLE -->                   
                
                <!-- PAGE CONTENT WRAPPER -->
                <div class="page-content-wrap">
                  <div class="row">                        
                    <div class="col-md-3 col-sm-4 col-xs-5">
                            
                            <form id="validate" action="javascript:MDouglasMS();" class="EditarEmail form-horizontal">
                            <div class="panel panel-default">                                
                                <div class="panel-body">
                                    <h3><span class="fa fa-user"></span> <?php echo $ExibirNome; ?></h3>
                                    <p><?php echo NivelAcesso(); ?></p>
                                </div>
                                <div class="panel-body form-group-separated">
                                    
                                    <div class="form-group">
                                        <label class="col-md-3 col-xs-5 control-label"><?php echo $_TRA['Usuario']; ?></label>
                                        <div class="col-md-9 col-xs-7">
                                            <input type="text" value="<?php echo $usuario; ?>" class="form-control" disabled/>
                                        </div>
                                    </div>
                                    
                                    <div class="form-group">
                                        <label class="col-md-3 col-xs-5 control-label"><?php echo $_TRA['email']; ?></label>
                                        <div class="col-md-9 col-xs-7">
                                            <input name="email" id="email" type="text" value="<?php echo $VerificarInfoOnline[2]; ?>" class="validate[required,custom[email]] form-control" />
                                        </div>
                                    </div>
                                    
                                     <div class="form-group">
                                        <div class="col-md-12 col-xs-5">
                                        	<div id="StatusEditarEmail"></div>
                                            <button class="EditarPerfilEmail btn btn-primary btn-rounded pull-right"><?php echo $_TRA['salvar']; ?></button>
                                        </div>
                                    </div>
                                    
                                    <div class="form-group">                                        
                                        <div class="col-md-12 col-xs-12">
                                            <a href="#" class="btn btn-danger btn-block btn-rounded" data-toggle="modal" data-target="#modal_change_password"><?php echo $_TRA['as']; ?></a>
                                        </div>
                                    </div>
                                    
                                    <div class="form-group">                                        
                                        <div class="col-md-12 col-xs-12">
                                            <a href="#" class="btn btn-info btn-block btn-rounded" data-toggle="modal" data-target="#modal_change_user"><?php echo $_TRA['au']; ?></a>
                                        </div>
                                    </div>
                                    
                                </div>
                            </div>
                            </form>
                            
                    </div>
                        <div class="col-md-6 col-sm-8 col-xs-7">
                            
                            <form name="EditarPerfil" id="validate" action="javascript:MDouglasMS();" class="EditarProfile form-horizontal">
                            <div class="panel panel-default">
                                <div class="panel-body">
                                    <h3><span class="fa fa-pencil"></span> <?php echo $_TRA['Perfil']; ?></h3>
                                    <p><?php echo $_TRA['EASIMSDSA']; ?></p>
                                </div>
                                <div class="panel-body form-group-separated">
                                    <div class="form-group">
                                        <label class="col-md-3 col-xs-5 control-label"><?php echo $_TRA['nome']; ?></label>
                                        <div class="col-md-9 col-xs-7">
                                            <input type="text" value="<?php echo $VerificarInfoOnline[0]; ?>" name="nome" id="nome" class="validate[required] form-control" />
                                        </div>
                                    </div>
                                    <div class="form-group">
                                        <label class="col-md-3 col-xs-5 control-label"><?php echo $_TRA['sobrenome']; ?></label>
                                        <div class="col-md-9 col-xs-7">
                                            <input type="text" value="<?php echo $VerificarInfoOnline[1]; ?>" name="sobrenome" id="sobrenome" class="validate[required] form-control" />
                                        </div>
                                    </div>
                                    <div class="form-group">
                                        <label class="col-md-3 col-xs-5 control-label"><?php echo $_TRA['celular']; ?></label>
                                        <div class="col-md-9 col-xs-7">
                                            <input type="text" value="<?php echo $VerificarInfoOnline[4]; ?>" name="celular" id="celular" class="mask_phone_ext validate[required,custom[phone]] form-control" />
                                        </div>
                                    </div>   
                                    <div class="form-group">
                                            <label class="col-md-3 col-xs-5 control-label"><?php echo $_TRA['dn']; ?></label>
                                            <div class="col-md-9">
                                                <div class="input-group date">
                                                    <input type="text" id="dp-3" name="DataNascimento" class="form-control" value="<?php echo $DataNascimento; ?>"/>
                                                    <span class="input-group-addon"><span class="glyphicon glyphicon-calendar"></span></span>
                                                </div>
                                            </div>
                                        </div>                                     
                                    <div class="form-group">
                                        <div class="col-md-12 col-xs-5">
                                        	<div id="StatusEditarPerfil"></div>
                                            <button class="EditarPerfil btn btn-primary btn-rounded pull-right"><?php echo $_TRA['salvar']; ?></button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            </form>
                        </div>
                        
                        <div class="col-md-3">
                            <div class="panel panel-default form-horizontal">
                                <div class="panel-body">
                                    <h3><span class="fa fa-info-circle"></span> <?php echo $_TRA['info']; ?></h3>
                                    <p><?php echo $_TRA['urisv']; ?></p>
                                </div>
                                <div class="panel-body form-group-separated">                                    
                                    <div class="form-group">
                                        <label class="col-md-4 col-xs-5 control-label"><?php echo $_TRA['ae']; ?></label>
                                        <div class="col-md-8 col-xs-7 line-height-30"><?php echo ConverterData($LnUser['data'], 3); ?></div>
                                    </div>
                                    <div class="form-group">
                                        <label class="col-md-4 col-xs-5 control-label"><?php echo $_TRA['uip']; ?></label>
                                        <div class="col-md-8 col-xs-7 line-height-30"><?php echo $LnUser['ip']; ?></div>
                                    </div>
                                    <div class="form-group">
                                        <label class="col-md-4 col-xs-5 control-label"><?php echo $_TRA['criadoem']; ?></label>
                                        <div class="col-md-8 col-xs-7 line-height-30"><?php echo $DataCadastro; ?></div>
                                    </div>
                                    <div class="form-group">
                                        <label class="col-md-4 col-xs-5 control-label"><?php echo $_TRA['grupo']; ?></label>
                                        <div class="col-md-8 col-xs-7"><?php echo NivelAcesso(); ?></div>
                                    </div>
                                    <div class="form-group">
                                        <label class="col-md-4 col-xs-5 control-label"><?php echo $_TRA['nascimento']; ?></label>
                                        <div class="col-md-8 col-xs-7 line-height-30"><?php echo $DataNascimento; ?></div>
                                    </div>
                                </div>
                                
                            </div>
                            
                        </div>
                        
                  </div>
                    

</div>
        
        <div class="modal animated fadeIn" id="modal_change_password" tabindex="-1" role="dialog" aria-labelledby="smallModalHead" aria-hidden="true">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <button type="button" class="close" data-dismiss="modal"><span aria-hidden="true">&times;</span><span class="sr-only"><?php echo $_TRA['fechar']; ?></span></button>
                        <h4 class="modal-title" id="smallModalHead"><?php echo $_TRA['as']; ?></h4>
                    </div>
                    <div class="modal-body form-horizontal form-group-separated">     
						<form id="validate" role="form" class="AlterarSenha form-horizontal" action="javascript:MDouglasMS();">
                        <div class="form-group">
                            <label class="col-md-3 control-label"><?php echo $_TRA['sa']; ?></label>
                            <div class="col-md-9">
                                <input type="password" class="validate[required] form-control" name="old_password" id="old_password"/>
                            </div>
                        </div>
                        <div class="form-group">
                            <label class="col-md-3 control-label"><?php echo $_TRA['ns']; ?></label>
                            <div class="col-md-9">
                                <input type="password" class="validate[required] form-control" name="new_password" id="new_password"/>
                            </div>
                        </div>
                        <div class="form-group">
                            <label class="col-md-3 control-label"><?php echo $_TRA['rns']; ?></label>
                            <div class="col-md-9">
                                <input type="password" class="validate[required,equals[new_password]] form-control" name="re_password" id="re_password"/>
                            </div>
                        </div>
						</form>
                    </div>
                    <div class="modal-footer">
						<div id="StatusAlterarSenha"></div>
                        <button type="button" class="AlterarSenha btn btn-danger"><?php echo $_TRA['alterar']; ?></button>
                        <button type="button" class="btn btn-default" data-dismiss="modal"><?php echo $_TRA['fechar']; ?></button>
                    </div>
                </div>
            </div>
        </div>   
        
        
        <div class="modal animated fadeIn" id="modal_change_user" tabindex="-1" role="dialog" aria-labelledby="smallModalHead" aria-hidden="true">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <button type="button" class="close" data-dismiss="modal"><span aria-hidden="true">&times;</span><span class="sr-only"><?php echo $_TRA['fechar']; ?></span></button>
                        <h4 class="modal-title" id="smallModalHead"><?php echo $_TRA['au']; ?></h4>
                    </div>
                    <div class="modal-body form-horizontal form-group-separated">     
						<form id="validate" role="form" class="FormAlterarUser form-horizontal" action="javascript:MDouglasMS();">
                        <div class="form-group">
                            <label class="col-md-3 control-label"><?php echo $_TRA['ua']; ?></label>
                            <div class="col-md-9">
                                <input value="<?php echo $usuario; ?>" type="text" class="validate[required] form-control" disabled="disabled" />
                            </div>
                        </div>
                        <div class="form-group">
                            <label class="col-md-3 control-label"><?php echo $_TRA['nu']; ?></label>
                            <div class="col-md-9">
                                <input type="text" class="validate[required] form-control" name="new_user" id="new_user"/>
                            </div>
                        </div>
                     
						</form>
                    </div>
                    <div class="modal-footer">
						<div id="StatusAlterarUser"></div>
                        <button type="button" class="AlterarUser btn btn-danger"><?php echo $_TRA['alterar']; ?></button>
                        <button type="button" class="btn btn-default" data-dismiss="modal"><?php echo $_TRA['fechar']; ?></button>
                    </div>
                </div>
            </div>
        </div>     
        <!-- EOF MODALS -->
        
        <!-- BLUEIMP GALLERY -->
        <div id="blueimp-gallery" class="blueimp-gallery blueimp-gallery-controls">
            <div class="slides"></div>
            <h3 class="title"></h3>
            <a class="prev">‹</a>
            <a class="next">›</a>
            <a class="close">×</a>
            <a class="play-pause"></a>
            <ol class="indicator"></ol>
        </div>      

		<div id="StatusGeral"></div>

<!-- START SCRIPTS -->
        <!-- START PLUGINS -->
        <script type="text/javascript" src="js/plugins/jquery/jquery.min.js"></script>
        <script type="text/javascript" src="js/plugins/jquery/jquery-ui.min.js"></script>
        <script type="text/javascript" src="js/plugins/bootstrap/bootstrap.min.js"></script>
        
        <script type="text/javascript" src="js/plugins/jquery/jquery-migrate.min.js"></script>
        <!-- END PLUGINS -->

        <!-- START THIS PAGE PLUGINS-->        
        <script type='text/javascript' src='js/plugins/icheck/icheck.min.js'></script>
        <script type="text/javascript" src="js/plugins/mcustomscrollbar/jquery.mCustomScrollbar.min.js"></script>  
        
        <script type="text/javascript" src="js/plugins/bootstrap/bootstrap-file-input.js"></script>
        <script type="text/javascript" src="js/plugins/form/jquery.form.js"></script>
        
        <script type="text/javascript" src="js/plugins/cropper/cropper.min.js"></script>
		
        <script type='text/javascript' src='js/plugins/validationengine/languages/jquery.validationEngine<?php echo Idioma(2); ?>.js'></script>
        <script type='text/javascript' src='js/plugins/validationengine/jquery.validationEngine.js'></script>     
        
        <script type='text/javascript' src='js/plugins/maskedinput/jquery.maskedinput.min.js'></script>  
        
        <script type="text/javascript" src="js/plugins/bootstrap/bootstrap-datepicker.js"></script>
        <script type="text/javascript" src="js/plugins/bootstrap/locales/bootstrap-datepicker<?php echo Idioma(2); ?>.js"></script>

        <!-- END THIS PAGE PLUGINS-->        

        <!-- START TEMPLATE -->
        <?php include_once("js/settings".Idioma(2).".php"); ?> 
        <script type="text/javascript" src="js/plugins.js"></script>        
        <script type="text/javascript" src="js/actions.js"></script>
        <!-- END TEMPLATE -->

    <!-- END SCRIPTS -->    
<?php
}else{
	echo Redirecionar('login.php');
}	
?>