<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAdmin = array('TesteVisualizar', 'TesteBloquear', 'TesteExcluir', 'TesteMensagem');
$VerificarAcesso = VerificarAcesso('teste', $ColunaAdmin);
$AdminVisualizar = $VerificarAcesso[0];
$AdminBloquear = $VerificarAcesso[1];
$AdminExcluir = $VerificarAcesso[2];
$AdminMensagem = $VerificarAcesso[3];
	
if($AdminVisualizar == 'S'){
?>

<script type='text/javascript'>
$(function(){  
 			$("a.ExibirOpcoes").click(function() { 
			
			var status = $(this).attr("status"); 
			
			if(status == 'arvore'){
				statusE = '<?php echo $_TRA['ar']; ?>';
			}
			else if(status == 'perfil'){
				statusE = '<?php echo $_TRA['ap']; ?>';
			}
			else if(status == 'bloquear'){
		
				statusE = '<?php echo $_TRA['bloquear']; ?>';
				var fa = 'fa fa-lock'; 
				var tipo = 'danger';
			}
			else if(status == 'desbloquear'){
				statusE = '<?php echo $_TRA['desbloquear']; ?>';
				var fa = 'fa fa-unlock-alt'; 
				var tipo = 'success';
			}
			else if(status == 'excluir'){
				statusE = '<?php echo $_TRA['excluir']; ?>';
				var fa = 'fa fa-trash-o'; 
				var tipo = 'danger';
			}
			else if(status == 'tornaruser'){
				statusE = 'Tornar Usuário';
				var fa = 'fa fa-user'; 
				var tipo = 'warning';
			}
			else{
				statusE = '<?php echo $_TRA['opcoes']; ?>';
				var fa = 'fa fa-gear'; 
				var tipo = 'danger';
			}

			$("#StatusEG").html(statusE);
						
			camposMarcados = new Array();
			$("input[type=checkbox][name='SelectUser[]']:checked").each(function(){
    		camposMarcados.push($(this).val());
			});
			
			if(status == 'arvore'){
				
					panel_refresh($(".page-container"));
				
					$.post('ScriptModalAlterarArvoreTeste.php', {camposMarcados: camposMarcados}, function(resposta) {
						
						setTimeout(panel_refresh($(".page-container")),500);
						
						$("#StatusGeral").html('');
						$("#StatusGeral").html(resposta);
					});
			}
			else if(status == 'perfil'){
				
					panel_refresh($(".page-container"));
				
					$.post('ScriptModalAlterarPerfilTeste.php', {camposMarcados: camposMarcados}, function(resposta) {
						
						setTimeout(panel_refresh($(".page-container")),500);
						
						$("#StatusGeral").html('');
						$("#StatusGeral").html(resposta);
					});
			}
			else if(status == 'email'){
				
					panel_refresh($(".page-container"));
				
					$.post('ScriptModalEnviarMensagemMassaTeste.php', {camposMarcados: camposMarcados}, function(resposta) {
						
						setTimeout(panel_refresh($(".page-container")),500);
						
						$("#StatusGeral").html('');
						$("#StatusGeral").html(resposta);
					});
			}
			else{
					var titulo = statusE + '?';
					var texto = 'Tem certeza que deseja '+statusE+'?';
					var url = 'EnviarOpcoesTeste';
					$.post('ScriptAlertaJS2.php', {camposMarcados: camposMarcados, status: status, titulo: titulo, texto: texto, tipo: tipo, url: url, fa: fa}, function(resposta) {
						$("#StatusGeral").html('');
						$("#StatusGeral").html(resposta);
					});
				}
			});
		});
</script>

<button type="button" class="btn btn-default"><span id="StatusEG"><?php echo $_TRA['opcoes']; ?></span></button>
<button type="button" class="btn btn-default dropdown-toggle" data-toggle="dropdown" aria-expanded="false"><span class="caret"></span></button>
<ul class="dropdown-menu" role="menu">

<?php
echo "<li><a status=\"tornaruser\" class=\"ExibirOpcoes pointer\">Tornar Usuário</a></li>";
							
echo "<li><a status=\"arvore\" class=\"ExibirOpcoes pointer\">".$_TRA['ar']."</a></li>";

echo "<li><a status=\"perfil\" class=\"ExibirOpcoes pointer\">".$_TRA['ap']."</a></li>";

if($AdminBloquear == "S"){
echo "<li><a status=\"bloquear\" class=\"ExibirOpcoes pointer\">".$_TRA['bloquear']."</a></li>
<li><a status=\"desbloquear\" class=\"ExibirOpcoes pointer\">".$_TRA['desbloquear']."</a></li>";
}

if($AdminExcluir == "S"){
echo "<li><a status=\"excluir\" class=\"ExibirOpcoes pointer\">".$_TRA['excluir']."</a></li>";
}
							
if($AdminMensagem == "S"){
echo "<li><a status=\"email\" class=\"ExibirOpcoes pointer\">Enviar E-mail</a></li>";
}
?>
</ul>
&nbsp;&nbsp; 

<?php
}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}	
?>